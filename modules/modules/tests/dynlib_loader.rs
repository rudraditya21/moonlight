use std::path::{Path, PathBuf};

use modules::{load_dyn_module, ModuleContext};

#[test]
fn dynlib_loader_smoke() {
    let lib_path = find_dynlib().expect("dynlib not built");
    let mut module = load_dyn_module(&lib_path).expect("load dynlib module");
    assert_eq!(module.metadata().name, "auxiliary/test/dynlib_echo");
    module.options_mut().set("INPUT", "world").expect("set");
    let result = module
        .run(&ModuleContext { session_id: 1 })
        .expect("run");
    assert!(result.success);
    assert!(result.message.contains("echo: world"));
}

fn find_dynlib() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())?;
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target = workspace_root.join("target").join(profile);
    let _ = build_dynlib(workspace_root);
    locate_dynlib(&target).or_else(|| locate_dynlib(&target.join("deps")))
}

fn locate_dynlib(dir: &Path) -> Option<PathBuf> {
    let prefix = dynlib_prefix();
    let ext = dynlib_ext();
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(ext) {
            return Some(path);
        }
    }
    None
}

fn dynlib_prefix() -> &'static str {
    if cfg!(target_os = "windows") {
        "moonlight_dynlib_test"
    } else {
        "libmoonlight_dynlib_test"
    }
}

fn dynlib_ext() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

fn build_dynlib(workspace_root: &Path) -> Result<(), String> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(workspace_root)
        .arg("build")
        .arg("-p")
        .arg("dynlib_test");
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("cargo build failed".to_string());
    }
    Ok(())
}
