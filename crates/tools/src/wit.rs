//! WIT handling for the build: parse interface files into one `Resolve`, select
//! a component's world, list capability-bindable exports, and embed
//! component-type metadata into modules.

use anyhow::{Context, Result};
use wit_component::StringEncoding;
use wit_parser::{Function, InterfaceId, PackageId, Resolve, WorldId, WorldItem, WorldKey};

/// A parsed WIT document (one `Resolve` covering all interface files).
pub struct Wit {
    resolve: Resolve,
    pkgs: Vec<PackageId>,
}

/// One named export of a world (an interface or a freestanding function).
pub struct WorldExport {
    /// Kebab-name of the export (matches the capability `name`, e.g. `spatial-query`).
    pub name: String,
    pub functions: Vec<FunctionExport>,
}

pub struct FunctionExport {
    pub name: String,
    pub signature: String,
    /// Whether the signature needs the caf-abi memory bridge (complex
    /// params/results — anything beyond scalars).
    pub needs_bridge: bool,
    pub core_type: wasmparser::FuncType,
}

/// Parse one or more WIT source files into a single `Resolve`.
pub fn parse(wit_sources: &[String]) -> Result<Wit> {
    let mut resolve = Resolve::default();
    let mut pkgs = Vec::with_capacity(wit_sources.len());
    for (i, src) in wit_sources.iter().enumerate() {
        let pkg = resolve
            .push_str(format!("interface-{i}.wit"), src)
            .with_context(|| format!("parse WIT source #{i}"))?;
        pkgs.push(pkg);
    }
    Ok(Wit { resolve, pkgs })
}

/// Select a world by name; `None` auto-selects when there is exactly one.
pub fn world(wit: &Wit, name: Option<&str>) -> Result<WorldId> {
    wit.resolve
        .select_world(&wit.pkgs, name)
        .context("select world")
}

/// List the world's exports (interfaces and freestanding functions).
pub fn exports(wit: &Wit, world: WorldId) -> Vec<WorldExport> {
    let world = &wit.resolve.worlds[world];
    let mut out = Vec::new();
    for (key, item) in &world.exports {
        match item {
            WorldItem::Interface { id, .. } => {
                let name = key_name(&wit.resolve, key, Some(*id));
                let iface = &wit.resolve.interfaces[*id];
                let functions = iface
                    .functions
                    .iter()
                    .map(|(n, f)| FunctionExport {
                        name: n.clone(),
                        signature: func_signature(f),
                        needs_bridge: func_needs_memory_bridge(&wit.resolve, f),
                        core_type: core_signature(&wit.resolve, f),
                    })
                    .collect();
                out.push(WorldExport { name, functions });
            }
            WorldItem::Function(f) => {
                out.push(WorldExport {
                    name: f.name.clone(),
                    functions: vec![FunctionExport {
                        name: f.name.clone(),
                        signature: func_signature(f),
                        needs_bridge: func_needs_memory_bridge(&wit.resolve, f),
                        core_type: core_signature(&wit.resolve, f),
                    }],
                });
            }
            WorldItem::Type { .. } => {}
        }
    }
    out
}

/// Embed the component-type metadata (the world) into a core module, turning it
/// into a component-metadata-carrying binary. Used only for real component-model
/// modules; the demo's custom-ABI core module intentionally does not use this.
pub fn embed_metadata(wit: &Wit, world: WorldId, wasm: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = wasm.to_vec();
    wit_component::embed_component_metadata(
        &mut bytes,
        &wit.resolve,
        world,
        StringEncoding::UTF8,
        false,
    )
    .context("embed component metadata")?;
    Ok(bytes)
}

fn key_name(resolve: &Resolve, key: &WorldKey, id: Option<InterfaceId>) -> String {
    match key {
        WorldKey::Name(n) => n.clone(),
        WorldKey::Interface(_) => id
            .and_then(|i| resolve.interfaces[i].name.clone())
            .unwrap_or_default(),
    }
}

fn func_signature(f: &Function) -> String {
    let params = f
        .params
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let result = if f.result.is_some() { " -> result" } else { "" };
    format!("func({params}){result}")
}

/// A WIT type needs the caf-abi memory bridge unless it is a plain scalar
/// (bool/char/int/float, plus flags and enums, which lower to integers).
fn type_needs_bridge(resolve: &Resolve, ty: &wit_parser::Type) -> bool {
    use wit_parser::{Type, TypeDefKind};
    match ty {
        Type::String | Type::ErrorContext => true,
        Type::Id(id) => match &resolve.types[*id].kind {
            TypeDefKind::Type(inner) => type_needs_bridge(resolve, inner),
            TypeDefKind::Flags(flags) => flags.flags.len() > 32,
            TypeDefKind::Enum(_) => false,
            _ => true,
        },
        _ => false,
    }
}

/// Whether a WIT function's params or result need the caf-abi memory bridge.
pub fn func_needs_memory_bridge(resolve: &Resolve, f: &Function) -> bool {
    f.params.iter().any(|p| type_needs_bridge(resolve, &p.ty))
        || f.result.is_some_and(|t| type_needs_bridge(resolve, &t))
}

/// caf-abi v1 passes complex parameters as (i32, i32) and complex
/// results as one packed i64. Type aliases lower exactly like their target.
fn core_scalar(resolve: &Resolve, ty: &wit_parser::Type) -> wasmparser::ValType {
    use wasmparser::ValType;
    use wit_parser::{Type, TypeDefKind};
    match ty {
        Type::U64 | Type::S64 => ValType::I64,
        Type::F32 => ValType::F32,
        Type::F64 => ValType::F64,
        Type::Id(id) => match &resolve.types[*id].kind {
            TypeDefKind::Type(inner) => core_scalar(resolve, inner),
            _ => ValType::I32,
        },
        _ => ValType::I32,
    }
}

fn core_signature(resolve: &Resolve, f: &Function) -> wasmparser::FuncType {
    use wasmparser::ValType;
    let mut params = Vec::new();
    for param in &f.params {
        if type_needs_bridge(resolve, &param.ty) {
            params.extend([ValType::I32, ValType::I32]);
        } else {
            params.push(core_scalar(resolve, &param.ty));
        }
    }
    let results: Vec<_> = f
        .result
        .map(|ty| {
            if type_needs_bridge(resolve, &ty) {
                ValType::I64
            } else {
                core_scalar(resolve, &ty)
            }
        })
        .into_iter()
        .collect();
    wasmparser::FuncType::new(params, results)
}
