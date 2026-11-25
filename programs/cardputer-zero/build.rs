//! Places the profile `pocket build` exported for this program in OUT_DIR,
//! compiles engine/worker's C runtime against the QuickJS-NG source Cargo
//! resolved for rquickjs, and statically links official `libghostty-vt` + `shim.c`.
use std::{env, path::PathBuf, process::Command};

fn main() {
    pocket_profile_build::emit(pocket_profile_build::Export::Required);
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.join("../..");
    let worker = root.join("engine/worker");
    println!("cargo:rerun-if-changed={}", worker.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        worker.join("include").display()
    );
    let mut build = cc::Build::new();
    build
        .include(worker.join("include"))
        .include(quickjs(&root))
        .define("_GNU_SOURCE", None)
        .flag_if_supported("-std=c11");
    for name in ["worker.c", "quickjs.c", "quickjs_ui.c", "runner.c"] {
        build.file(worker.join("src").join(name));
    }
    build.compile("pocket_worker");

    // Compile `native/ghostty/shim.c` and link prebuilt `libghostty-vt.a`.
    let rex_zero_root = env::var_os("REX_ZERO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("../.."));
    let target = env::var("TARGET").expect("TARGET");
    let ghostty_prefix = if target.starts_with("aarch64-unknown-linux") {
        rex_zero_root.join(".build/ghostty/prefix-linux-arm64")
    } else {
        rex_zero_root.join(".build/ghostty/prefix-host")
    };
    let shim_dir = rex_zero_root.join("native/ghostty");
    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.c").display());
    println!("cargo:rerun-if-changed={}", shim_dir.join("shim.h").display());
    println!(
        "cargo:rerun-if-changed={}",
        ghostty_prefix.join("lib/libghostty-vt.a").display()
    );

    let mut ghostty_shim = cc::Build::new();
    ghostty_shim
        .file(shim_dir.join("shim.c"))
        .include(&shim_dir)
        .include(ghostty_prefix.join("include"))
        .define("GHOSTTY_STATIC", None)
        .flag_if_supported("-std=c11");
    ghostty_shim.compile("rexpocket_ghostty_shim");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let static_lib_dir = out_dir.join("ghostty-static");
    std::fs::create_dir_all(&static_lib_dir).expect("create ghostty-static dir");
    let src_archive = ghostty_prefix.join("lib/libghostty-vt.a");
    let dst_archive = static_lib_dir.join("libghostty-vt.a");
    let need_copy = match (std::fs::metadata(&src_archive), std::fs::metadata(&dst_archive)) {
        (Ok(s), Ok(d)) => s.len() != d.len(),
        _ => true,
    };
    if need_copy {
        std::fs::copy(&src_archive, &dst_archive).expect("stage libghostty-vt.a");
    }

    println!("cargo:rustc-link-search=native={}", static_lib_dir.display());
    println!("cargo:rustc-link-lib=static=ghostty-vt");
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
    }
}

/// The `quickjs/` directory of the rquickjs-sys package in the workspace lock
/// (tools/test-quickjs-guest.ts finds it the same way).
fn quickjs(root: &std::path::Path) -> PathBuf {
    let target = env::var("TARGET").expect("TARGET");
    let output = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args([
            "metadata",
            "--locked",
            "--format-version=1",
            "--filter-platform",
            &target,
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let manifest = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|package| package["name"] == "rquickjs-sys")
        .and_then(|package| package["manifest_path"].as_str())
        .expect("cargo metadata has no rquickjs-sys package");
    PathBuf::from(manifest)
        .parent()
        .expect("rquickjs-sys manifest directory")
        .join("quickjs")
}
