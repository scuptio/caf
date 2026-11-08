//! CAF security core: the single place where authorization decisions are made.
//!
//! This crate is deliberately **pure, sequential, and free of ambient I/O** so
//! that it can be translated to a Lean model (via Charon/Aeneas) and refined
//! against the CAF security theorems. It has two halves:
//!
//! - **Admission** (`resolve_imports`): a pure function from the artifact's
//!   declared policy and a component's requested imports to a grant set. The
//!   runtime only constructs linker entries for granted imports, so a component
//!   structurally cannot reach an undeclared host capability (fail-closed).
//! - **Metering** (`Meter`): per-effect budget accounting for the resource
//!   dimensions the Wasm engine does not enforce itself (read, output). Every
//!   charge is monotone: budgets only shrink.

use caf_core::manifest::{CapabilityPolicy, ExecutionProfile, ResourceLimits};

/// Host function groups of the `caf` ABI, classified by the capability they
/// require. Anything outside these two groups is undeclared and rejected.
pub const PAYLOAD_FS_FUNCS: &[&str] = &["open", "read", "readdir", "stat", "seek", "close"];
/// Meta host functions (introspection, output, abort) available to every
/// component regardless of policy.
pub const META_FUNCS: &[&str] = &["self_size", "emit", "log", "abort"];

/// A single import requested by a component (module + name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Import module; only `caf` (the host ABI) is declared.
    pub module: String,
    /// Import name within the module.
    pub name: String,
}

impl Import {
    /// Build an import from its module and name.
    pub fn new(module: &str, name: &str) -> Self {
        Self {
            module: module.to_string(),
            name: name.to_string(),
        }
    }
}

/// What the runtime is allowed to provide to a component after admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grants {
    /// The read-only, scope-restricted payload filesystem.
    pub payload_fs: bool,
}

/// Why an artifact/component was rejected at admission time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The manifest declares a capability this runtime does not implement.
    /// Declared-but-unsupported is a hard error, not a silent no-op.
    UnsupportedCapability(&'static str),
    /// The component imports something outside the `caf` host ABI.
    UndeclaredImport {
        /// Import module.
        module: String,
        /// Import name.
        name: String,
    },
    /// The component imports a payload-fs function but `self_read` is false.
    CapabilityNotGranted {
        /// The `caf.*` function imported without the grant.
        name: String,
    },
    /// The manifest names an execution profile this runtime cannot enforce.
    /// Profiles are machine-checkable configuration sets; an unknown one is a
    /// dead declaration, so it is rejected rather than silently ignored.
    UnsupportedProfile(String),
    /// The named profile requires `deterministic: true` but the manifest
    /// declares otherwise — a contradictory, unenforceable combination.
    ProfileRequiresDeterministic(String),
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::UnsupportedCapability(c) => {
                write!(
                    f,
                    "declared capability '{c}' is not supported by this runtime"
                )
            }
            AdmissionError::UndeclaredImport { module, name } => {
                write!(
                    f,
                    "component imports undeclared host function '{module}.{name}'"
                )
            }
            AdmissionError::CapabilityNotGranted { name } => {
                write!(
                    f,
                    "component imports 'caf.{name}' but self_read is not granted"
                )
            }
            AdmissionError::UnsupportedProfile(p) => {
                write!(
                    f,
                    "execution profile '{p}' is not supported by this runtime"
                )
            }
            AdmissionError::ProfileRequiresDeterministic(p) => {
                write!(f, "execution profile '{p}' requires deterministic = true")
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Fail-fast check of the policy flags alone (artifact open time).
pub fn check_policy_supported(policy: &CapabilityPolicy) -> Result<(), AdmissionError> {
    if policy.network {
        return Err(AdmissionError::UnsupportedCapability("network"));
    }
    if policy.filesystem {
        return Err(AdmissionError::UnsupportedCapability("filesystem"));
    }
    if policy.clock {
        return Err(AdmissionError::UnsupportedCapability("clock"));
    }
    if policy.random {
        return Err(AdmissionError::UnsupportedCapability("random"));
    }
    Ok(())
}

/// The deterministic execution profile: canonical NaN semantics, no
/// platform-dependent relaxed-SIMD, no threads, no clock/random/environment
/// host imports, and a deterministic out-of-fuel trap.
pub const PROFILE_CAF_D1: &str = "caf-d1";

/// Fail-closed check of the declared execution profile (artifact open time).
///
/// A profile is a machine-checkable engine configuration. This runtime knows
/// only `caf-d1`; anything else is a declaration it cannot enforce and is
/// rejected rather than ignored.
pub fn check_execution_profile(exec: &ExecutionProfile) -> Result<(), AdmissionError> {
    match exec.profile.as_str() {
        PROFILE_CAF_D1 if exec.deterministic => Ok(()),
        PROFILE_CAF_D1 => Err(AdmissionError::ProfileRequiresDeterministic(
            exec.profile.clone(),
        )),
        other => Err(AdmissionError::UnsupportedProfile(other.to_string())),
    }
}

/// Admission: resolve a component's requested imports against the artifact's
/// declared policy. On success, the returned [`Grants`] is the *only* set of
/// host functions the runtime may provide.
pub fn resolve_imports(
    policy: &CapabilityPolicy,
    imports: &[Import],
) -> Result<Grants, AdmissionError> {
    check_policy_supported(policy)?;
    let grants = Grants {
        payload_fs: policy.self_read,
    };
    for imp in imports {
        if imp.module != "caf" {
            return Err(AdmissionError::UndeclaredImport {
                module: imp.module.clone(),
                name: imp.name.clone(),
            });
        }
        if PAYLOAD_FS_FUNCS.contains(&imp.name.as_str()) {
            if !grants.payload_fs {
                return Err(AdmissionError::CapabilityNotGranted {
                    name: imp.name.clone(),
                });
            }
        } else if !META_FUNCS.contains(&imp.name.as_str()) {
            return Err(AdmissionError::UndeclaredImport {
                module: imp.module.clone(),
                name: imp.name.clone(),
            });
        }
    }
    Ok(grants)
}

/// Declared resource budgets (the protocol-level, deterministic budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    /// Maximum guest linear memory, in bytes.
    pub memory_max: u64,
    /// CPU budget, in fuel units.
    pub fuel_max: u64,
    /// Maximum bytes fetched from the payload backing store.
    pub read_max: u64,
    /// Maximum bytes of output (emit/log, results, host memory reads).
    pub output_max: u64,
}

impl From<&ResourceLimits> for Budgets {
    fn from(r: &ResourceLimits) -> Self {
        Self {
            memory_max: r.memory_max,
            fuel_max: r.cpu_fuel,
            read_max: r.read_max,
            output_max: r.output_max,
        }
    }
}

/// Runtime meter for the budgets enforced at the host boundary.
///
/// `fuel` is enforced by the Wasm engine and `memory` by the store limiter, so
/// the meter only tracks the two dimensions that cross host functions: bytes
/// read from the payload backing store and bytes emitted as output. Charging is
/// monotone and never wraps.
#[derive(Clone, Debug)]
pub struct Meter {
    budgets: Budgets,
    read_used: u64,
    output_used: u64,
}

impl Meter {
    /// A meter with zero usage against `budgets`.
    pub fn new(budgets: Budgets) -> Self {
        Self {
            budgets,
            read_used: 0,
            output_used: 0,
        }
    }

    /// Charge `n` bytes fetched from the payload backing store.
    pub fn charge_read(&mut self, n: u64) -> bool {
        charge(&mut self.read_used, self.budgets.read_max, n)
    }

    /// Charge `n` bytes crossing the host boundary as output (emit / log).
    pub fn charge_output(&mut self, n: u64) -> bool {
        charge(&mut self.output_used, self.budgets.output_max, n)
    }

    /// The budgets this meter enforces.
    pub fn budgets(&self) -> Budgets {
        self.budgets
    }

    /// Bytes charged against the read budget so far.
    pub fn read_used(&self) -> u64 {
        self.read_used
    }

    /// Bytes charged against the output budget so far.
    pub fn output_used(&self) -> u64 {
        self.output_used
    }
}

fn charge(used: &mut u64, max: u64, n: u64) -> bool {
    // Overflow means the charge exceeds any representable budget: deny it
    // rather than saturate (saturating would make further charges free once
    // `used` reached u64::MAX).
    let Some(next) = used.checked_add(n) else {
        return false;
    };
    if next > max {
        return false;
    }
    *used = next;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(self_read: bool) -> CapabilityPolicy {
        CapabilityPolicy {
            self_read,
            network: false,
            filesystem: false,
            clock: false,
            random: false,
        }
    }

    fn exec(profile: &str, deterministic: bool) -> ExecutionProfile {
        ExecutionProfile {
            profile: profile.to_string(),
            deterministic,
        }
    }

    #[test]
    fn caf_d1_requires_deterministic() {
        assert_eq!(check_execution_profile(&exec("caf-d1", true)), Ok(()));
        assert_eq!(
            check_execution_profile(&exec("caf-d1", false)),
            Err(AdmissionError::ProfileRequiresDeterministic(
                "caf-d1".to_string()
            ))
        );
    }

    #[test]
    fn unknown_profile_fails_closed() {
        assert_eq!(
            check_execution_profile(&exec("caf-fast", true)),
            Err(AdmissionError::UnsupportedProfile("caf-fast".to_string()))
        );
        assert!(matches!(
            check_execution_profile(&exec("caf-fast", false)),
            Err(AdmissionError::UnsupportedProfile(_))
        ));
    }

    #[test]
    fn grants_payload_fs_when_self_read() {
        let imports = vec![
            Import::new("caf", "open"),
            Import::new("caf", "read"),
            Import::new("caf", "self_size"),
            Import::new("caf", "emit"),
        ];
        let grants = resolve_imports(&policy(true), &imports);
        assert_eq!(grants, Ok(Grants { payload_fs: true }));
    }

    #[test]
    fn rejects_fs_import_without_self_read() {
        let imports = vec![Import::new("caf", "open")];
        let err = resolve_imports(&policy(false), &imports);
        assert_eq!(
            err,
            Err(AdmissionError::CapabilityNotGranted {
                name: "open".to_string()
            })
        );
    }

    #[test]
    fn rejects_undeclared_import() {
        let imports = vec![Import::new("evil", "net")];
        let err = resolve_imports(&policy(true), &imports);
        assert_eq!(
            err,
            Err(AdmissionError::UndeclaredImport {
                module: "evil".to_string(),
                name: "net".to_string()
            })
        );
    }

    #[test]
    fn rejects_unknown_caf_function() {
        let imports = vec![Import::new("caf", "exec")];
        assert!(matches!(
            resolve_imports(&policy(true), &imports),
            Err(AdmissionError::UndeclaredImport { .. })
        ));
    }

    #[test]
    fn rejects_declared_but_unsupported_capability() {
        let mut p = policy(true);
        p.network = true;
        assert_eq!(
            resolve_imports(&p, &[]),
            Err(AdmissionError::UnsupportedCapability("network"))
        );
    }

    #[test]
    fn meter_is_monotone_and_bounded() {
        let budgets = Budgets {
            memory_max: 0,
            fuel_max: 0,
            read_max: 10,
            output_max: 4,
        };
        let mut m = Meter::new(budgets);
        assert!(m.charge_read(6));
        assert!(!m.charge_read(5)); // 6 + 5 > 10
        assert!(m.charge_read(4)); // exactly at the bound
        assert!(!m.charge_read(1));
        assert_eq!(m.read_used(), 10);

        assert!(m.charge_output(4));
        assert!(!m.charge_output(1));
        assert_eq!(m.output_used(), 4);
    }

    #[test]
    fn charge_never_wraps() {
        let budgets = Budgets {
            memory_max: 0,
            fuel_max: 0,
            read_max: u64::MAX,
            output_max: 0,
        };
        let mut m = Meter::new(budgets);
        assert!(m.charge_read(u64::MAX));
        assert!(!m.charge_read(1)); // saturates, no wrap, still bounded
        assert_eq!(m.read_used(), u64::MAX);
    }
}
