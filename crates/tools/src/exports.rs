//! Best-effort export enumeration of WASM modules and components: the fallback
//! used for the manifest's export list when no WIT world is declared.

use caf_core::manifest::ExportEntry;
use wasmparser::{ComponentExternalKind, ExternalKind, Parser, Payload};

/// Extract the export names of a WASM module or component (best-effort). Both
/// core modules and component-model binaries are inspected; anything unparseable
/// yields an empty list. The export→capability binding is performed by the WIT
/// world at load time, which is out of scope for the build tool, so `capability`
/// is left empty here.
pub fn extract_exports(wasm: &[u8]) -> Vec<ExportEntry> {
    let mut out = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => return out,
        };
        match payload {
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = match export {
                        Ok(e) => e,
                        Err(_) => return out,
                    };
                    out.push(ExportEntry {
                        capability: String::new(),
                        export: export.name.to_string(),
                        signature: core_kind(export.kind).to_string(),
                    });
                }
            }
            Payload::ComponentExportSection(reader) => {
                for export in reader {
                    let export = match export {
                        Ok(e) => e,
                        Err(_) => return out,
                    };
                    out.push(ExportEntry {
                        capability: String::new(),
                        export: export.name.full_name().into_owned(),
                        signature: component_kind(export.kind).to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

fn core_kind(kind: ExternalKind) -> &'static str {
    match kind {
        ExternalKind::Func => "func",
        ExternalKind::Table => "table",
        ExternalKind::Memory => "memory",
        ExternalKind::Global => "global",
        ExternalKind::Tag => "tag",
        ExternalKind::FuncExact => "func",
    }
}

fn component_kind(kind: ComponentExternalKind) -> &'static str {
    use ComponentExternalKind::*;
    match kind {
        Module => "module",
        Func => "func",
        Value => "value",
        Type => "type",
        Instance => "instance",
        Component => "component",
    }
}

/// Validated v1 core exports, retaining the real export name for invocation.
pub struct CoreExports {
    pub functions: std::collections::HashMap<String, (String, wasmparser::FuncType)>,
    pub memory32: bool,
}

pub fn core_exports(wasm: &[u8]) -> anyhow::Result<CoreExports> {
    use anyhow::{Context, bail};
    use wasmparser::{Encoding, TypeRef, Validator};
    Validator::new()
        .validate_all(wasm)
        .context("validate WASM module")?;
    let mut types = Vec::new();
    let mut functions = Vec::new();
    let mut memories = Vec::new();
    let mut exports = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::Version {
                encoding: Encoding::Component,
                ..
            } => {
                bail!("format v1 requires a core WASM module");
            }
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    types.push(ty?);
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    match import?.ty {
                        TypeRef::Func(index) | TypeRef::FuncExact(index) => functions.push(index),
                        TypeRef::Memory(memory) => memories.push(memory),
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for index in reader {
                    functions.push(index?);
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    memories.push(memory?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    exports.push(export?);
                }
            }
            _ => {}
        }
    }
    let mut out = CoreExports {
        functions: Default::default(),
        memory32: false,
    };
    for export in exports {
        if export.kind == ExternalKind::Func {
            let ty_index = *functions
                .get(export.index as usize)
                .context("function index missing")?;
            let ty = types
                .get(ty_index as usize)
                .context("function type missing")?
                .clone();
            let name = export.name.replace('_', "-");
            if out
                .functions
                .insert(name.clone(), (export.name.to_string(), ty))
                .is_some()
            {
                bail!("ambiguous WASM export name '{name}' after caf-abi name normalization");
            }
        } else if export.kind == ExternalKind::Memory && export.name == "memory" {
            let memory = memories
                .get(export.index as usize)
                .context("memory index missing")?;
            out.memory32 = !memory.memory64 && !memory.shared;
        }
    }
    Ok(out)
}
