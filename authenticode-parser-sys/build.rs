use std::path::PathBuf;

pub fn cargo_rerun_if_env_changed(target: &str, env_var: &str) {
    println!("cargo:rerun-if-env-changed={}", env_var);
    println!("cargo:rerun-if-env-changed={}_{}", env_var, target);
    println!(
        "cargo:rerun-if-env-changed={}_{}",
        env_var,
        target.replace('-', "_")
    );
}

pub fn get_target_env_var(target: &str, env_var: &str) -> Option<String> {
    std::env::var(format!("{}_{}", env_var, target))
        .or_else(|_| std::env::var(format!("{}_{}", env_var, target.replace('-', "_"))))
        .or_else(|_| std::env::var(env_var))
        .ok()
}

fn main() {
    let target = std::env::var("TARGET").unwrap();

    let libdir = PathBuf::from("authenticode-parser");
    let srcdir = libdir.join("src");

    cargo_rerun_if_env_changed(&target, "OPENSSL_LIB_DIR");
    if let Some(openssl_lib_dir) = get_target_env_var(&target, "OPENSSL_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            PathBuf::from(openssl_lib_dir).display()
        );
    }

    let mut builder = cc::Build::new();
    builder
        .file(srcdir.join("authenticode.c"))
        .file(srcdir.join("helper.c"))
        .file(srcdir.join("structs.c"))
        .file(srcdir.join("countersignature.c"))
        .file(srcdir.join("certificate.c"))
        .include(libdir.join("include"));
    #[cfg(target_endian = "big")]
    builder.define("WORDS_BIGENDIAN");

    builder.compile("authenticode");

    println!("cargo:rustc-link-lib=static=authenticode");
    if target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=dylib=libcrypto");
    } else {
        println!("cargo:rustc-link-lib=dylib=crypto");
    }

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", libdir.join("include").display()))
        .header(
            libdir
                .join("include")
                .join("authenticode-parser")
                .join("authenticode.h")
                .display()
                .to_string(),
        )
        .allowlist_function("initialize_authenticode_parser")
        .allowlist_function("parse_authenticode")
        .allowlist_function("authenticode_new")
        .allowlist_function("authenticode_array_free")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
