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
