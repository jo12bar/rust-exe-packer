use std::{
    path::{Path, PathBuf},
    process::Command,
};

const RUSTC_LINK_ARGS: &[&str] = &["-nostartfiles", "-nodefaultlibs", "-static"];

fn main() {
    for arg in RUSTC_LINK_ARGS {
        println!("cargo:rustc-link-arg={}", arg);
    }

    cargo_build(&PathBuf::from("../stage1"));
    cargo_build(&PathBuf::from("../stage2"));
}

fn cargo_build(path: &Path) {
    println!("cargo:rerun-if-changed=..");

    let target_dir = format!("{}/embeds", std::env::var("OUT_DIR").unwrap());

    let output = Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--release")
        .current_dir(path)
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    if !output.status.success() {
        panic!(
            "Building {} failed.\nStdout: {}\nStderr: {}",
            path.display(),
            String::from_utf8_lossy(&output.stdout[..]),
            String::from_utf8_lossy(&output.stderr[..]),
        );
    }

    // Let's just assume the library has the same name as the crate.
    let lib_name = format!("lib{}.so", path.file_name().unwrap().to_str().unwrap());
    let output = Command::new("objcopy")
        .arg("--strip-all")
        .arg(&format!("release/{}", lib_name))
        .arg(lib_name)
        .current_dir(&target_dir)
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    if !output.status.success() {
        panic!(
            "Stripping failed.\nStdout: {}\nStderr: {}",
            String::from_utf8_lossy(&output.stdout[..]),
            String::from_utf8_lossy(&output.stderr[..]),
        )
    }
}
