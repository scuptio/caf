//! `caf-tool new`: scaffold a new CAF project (build config, WIT interface, and
//! a language skeleton) from askama templates.

use anyhow::{Context, Result, bail};
use askama::Template;
use clap::ValueEnum;
use std::path::Path;

/// Project skeleton languages for `caf-tool new`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Language {
    /// Rust (cargo build to wasm32-unknown-unknown).
    Rust,
    /// Python (componentize-py).
    Python,
    /// JavaScript (ComponentizeJS).
    #[value(name = "js", alias = "javascript")]
    JavaScript,
    /// Go via TinyGo.
    #[value(name = "go", alias = "tinygo")]
    TinyGo,
    /// ActionScript (asc).
    #[value(name = "as", alias = "actionscript")]
    ActionScript,
}

/// Create the project `dir/name`: `build.toml`, a WIT interface, a payload
/// directory, and a language skeleton. Fails on invalid names or when the
/// directory already exists.
pub fn scaffold(name: &str, lang: Language, dir: &Path) -> Result<()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        bail!("invalid project name '{name}'");
    }
    let root = dir.join(name);
    if root.exists() {
        bail!("directory {} already exists", root.display());
    }

    write_common(&root, name, lang)?;
    match lang {
        Language::Rust => write_rust(&root, name)?,
        Language::Python => write_python(&root, name)?,
        Language::JavaScript => write_javascript(&root, name)?,
        Language::TinyGo => write_tinygo(&root, name)?,
        Language::ActionScript => write_actionscript(&root, name)?,
    }
    println!("created {} ({lang:?})", root.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Templates (askama). Files live under `templates/` with a `.txt` extension so
// askama applies no escaping; the `.wit`/`.rs`/`.toml` contents are emitted raw.
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "build.toml.txt")]
struct BuildToml<'a> {
    name: &'a str,
    access: &'a str,
    build_block: &'a str,
}

#[derive(Template)]
#[template(path = "wit.txt")]
struct Wit<'a> {
    name: &'a str,
    with_hello: bool,
}

#[derive(Template)]
#[template(path = "readme.md.txt")]
struct Readme<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "rust/Cargo.toml.txt")]
struct RustCargo<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "rust/lib.rs.txt")]
struct RustLib<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "python/app.py.txt")]
struct PythonApp<'a> {
    name: &'a str,
    class_name: &'a str,
}

#[derive(Template)]
#[template(path = "javascript/component.js.txt")]
struct JsComponent<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "javascript/package.json.txt")]
struct JsPackage<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "tinygo/main.go.txt")]
struct GoMain<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "tinygo/go.mod.txt")]
struct GoMod<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "actionscript/Main.as.txt")]
struct AsMain<'a> {
    name: &'a str,
}

// ---------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------

/// The `[components.build]` block for the scaffolded `build.toml`: caf-tool
/// runs the command through the platform shell before packing, so no
/// per-language build script is needed. Languages whose toolchain emits
/// component-model binaries get a note that format v1 packs core WASM only.
fn build_block(name: &str, lang: Language) -> String {
    let (note, command, artifact) = match lang {
        Language::Rust => (
            "",
            "cargo build --release --target wasm32-unknown-unknown".to_string(),
            Some(format!(
                "target/wasm32-unknown-unknown/release/{}.wasm",
                name.replace('-', "_")
            )),
        ),
        Language::Python => (
            "# componentize-py emits a component-model binary; container format v1 packs\n# core WASM modules only, so the pack step is rejected today.\n",
            format!(
                "componentize-py -d interfaces/{name}.wit -w {name}-world componentize app -o {name}.wasm"
            ),
            None,
        ),
        Language::JavaScript => (
            "# jco emits a component-model binary; container format v1 packs core WASM\n# modules only, so the pack step is rejected today.\n",
            format!(
                "jco componentize src/component.js --wit interfaces/{name}.wit --world-name {name}-world -o {name}.wasm"
            ),
            None,
        ),
        Language::TinyGo => (
            "",
            format!("tinygo build -o {name}.wasm -target wasi main.go"),
            None,
        ),
        Language::ActionScript => return String::new(),
    };
    let artifact_line = artifact
        .map(|a| format!("artifact = \"{a}\"\n"))
        .unwrap_or_default();
    format!("\n\n{note}[components.build]\ncommand = \"{command}\"\n{artifact_line}")
}

fn write_common(root: &Path, name: &str, lang: Language) -> Result<()> {
    std::fs::create_dir_all(root.join("interfaces"))?;
    std::fs::create_dir_all(root.join("payload"))?;

    // The Rust skeleton ships the runnable hello demo: a bundled payload file
    // plus the access grant and the WIT declaration to read it.
    let with_hello = matches!(lang, Language::Rust);
    let access = if with_hello { "[\"/hello.txt\"]" } else { "[]" };
    let block = build_block(name, lang);
    render_to(
        root,
        "build.toml",
        &BuildToml {
            name,
            access,
            build_block: &block,
        },
    )?;
    render_to(
        root,
        &format!("interfaces/{name}.wit"),
        &Wit { name, with_hello },
    )?;
    render_to(root, "README.md", &Readme { name })?;
    if with_hello {
        std::fs::write(root.join("payload/hello.txt"), "Hello, CAF")?;
    } else {
        std::fs::write(root.join("payload/.gitkeep"), "")?;
    }
    Ok(())
}

fn write_rust(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "Cargo.toml", &RustCargo { name })?;
    render_to(root, "src/lib.rs", &RustLib { name })
}

fn pascal_case(name: &str) -> String {
    name.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn write_python(root: &Path, name: &str) -> Result<()> {
    let class_name = pascal_case(name);
    render_to(
        root,
        "app.py",
        &PythonApp {
            name,
            class_name: &class_name,
        },
    )
}

fn write_javascript(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "src/component.js", &JsComponent { name })?;
    render_to(root, "package.json", &JsPackage { name })
}

fn write_tinygo(root: &Path, name: &str) -> Result<()> {
    render_to(root, "main.go", &GoMain { name })?;
    render_to(root, "go.mod", &GoMod { name })
}

fn write_actionscript(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "src/Main.as", &AsMain { name })
}

fn render_to(root: &Path, rel: &str, template: &impl Template) -> Result<()> {
    let mut contents = template.render().context("render template")?;
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    let path = root.join(rel);
    std::fs::write(&path, contents).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
