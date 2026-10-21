use anyhow::{bail, Context, Result};
use askama::Template;
use clap::ValueEnum;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Language {
    Rust,
    Python,
    #[value(name = "js", alias = "javascript")]
    JavaScript,
    #[value(name = "go", alias = "tinygo")]
    TinyGo,
    #[value(name = "as", alias = "actionscript")]
    ActionScript,
}

pub fn scaffold(name: &str, lang: Language, dir: &Path) -> Result<()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        bail!("invalid project name '{name}'");
    }
    let root = dir.join(name);
    if root.exists() {
        bail!("directory {} already exists", root.display());
    }

    write_common(&root, name)?;
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
// askama applies no escaping; the `.wit`/`.rs`/`.sh` contents are emitted raw.
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "build.toml.txt")]
struct BuildToml<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "wit.txt")]
struct Wit<'a> {
    name: &'a str,
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
#[template(path = "rust/build.sh.txt")]
struct RustBuild<'a> {
    name: &'a str,
    crate_name: &'a str,
}

#[derive(Template)]
#[template(path = "python/app.py.txt")]
struct PythonApp<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "python/build.sh.txt")]
struct PythonBuild<'a> {
    name: &'a str,
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
#[template(path = "javascript/build.sh.txt")]
struct JsBuild<'a> {
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
#[template(path = "tinygo/build.sh.txt")]
struct GoBuild<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "actionscript/Main.as.txt")]
struct AsMain<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "actionscript/build.sh.txt")]
struct AsBuild<'a> {
    name: &'a str,
}

// ---------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------

fn write_common(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("interfaces"))?;
    std::fs::create_dir_all(root.join("payload"))?;

    render_to(root, "build.toml", &BuildToml { name })?;
    render_to(root, &format!("interfaces/{name}.wit"), &Wit { name })?;
    render_to(root, "README.md", &Readme { name })?;
    std::fs::write(root.join("payload/.gitkeep"), "")?;
    Ok(())
}

fn write_rust(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "Cargo.toml", &RustCargo { name })?;
    render_to(root, "src/lib.rs", &RustLib { name })?;
    let crate_name = name.replace('-', "_");
    render_to(root, "build.sh", &RustBuild { name, crate_name: &crate_name })
}

fn write_python(root: &Path, name: &str) -> Result<()> {
    render_to(root, "app.py", &PythonApp { name })?;
    render_to(root, "build.sh", &PythonBuild { name })
}

fn write_javascript(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "src/component.js", &JsComponent { name })?;
    render_to(root, "package.json", &JsPackage { name })?;
    render_to(root, "build.sh", &JsBuild { name })
}

fn write_tinygo(root: &Path, name: &str) -> Result<()> {
    render_to(root, "main.go", &GoMain { name })?;
    render_to(root, "go.mod", &GoMod { name })?;
    render_to(root, "build.sh", &GoBuild { name })
}

fn write_actionscript(root: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    render_to(root, "src/Main.as", &AsMain { name })?;
    render_to(root, "build.sh", &AsBuild { name })
}

fn render_to(root: &Path, rel: &str, template: &impl Template) -> Result<()> {
    let mut contents = template.render().context("render template")?;
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    let path = root.join(rel);
    std::fs::write(&path, contents).with_context(|| format!("write {}", path.display()))?;
    if rel == "build.sh" {
        make_executable(&path);
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
