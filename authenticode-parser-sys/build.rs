use std::path::PathBuf;

pub fn cargo_rerun_if_env_changed(target: &str, env_var: &str) {
    println!("cargo:rerun-if-env-changed={env_var}");
    println!("cargo:rerun-if-env-changed={env_var}_{target}");
    println!(
        "cargo:rerun-if-env-changed={}_{}",
        env_var,
        target.replace('-', "_")
    );
}

pub fn get_target_env_var(target: &str, env_var: &str) -> Option<String> {
    std::env::var(format!("{env_var}_{target}"))
        .or_else(|_| std::env::var(format!("{}_{}", env_var, target.replace('-', "_"))))
        .or_else(|_| std::env::var(env_var))
        .ok()
}

fn main() {
    let target = std::env::var("TARGET").unwrap();

    let libdir = PathBuf::from("authenticode-parser");
    let srcdir = libdir.join("src");

    cargo_rerun_if_env_changed(&target, "OPENSSL_DIR");
    cargo_rerun_if_env_changed(&target, "OPENSSL_INCLUDE_DIR");
    cargo_rerun_if_env_changed(&target, "OPENSSL_LIB_DIR");

    // If OPENSSL_DIR is set, use it to extrapolate lib and include dir
    let mut openssl_include_dir = None;
    if let Some(openssl_dir) = get_target_env_var(&target, "OPENSSL_DIR") {
        let openssl_dir = PathBuf::from(openssl_dir);

        openssl_include_dir = Some(openssl_dir.join("include"));
        println!(
            "cargo:rustc-link-search=native={}",
            openssl_dir.join("lib").display()
        );
    } else {
        // Otherwise, retrieve OPENSSL_INCLUDE_DIR and OPENSSL_LIB_DIR
        if let Some(include_dir) = get_target_env_var(&target, "OPENSSL_INCLUDE_DIR") {
            openssl_include_dir = Some(PathBuf::from(include_dir));
        }
        if let Some(openssl_lib_dir) = get_target_env_var(&target, "OPENSSL_LIB_DIR") {
            println!(
                "cargo:rustc-link-search=native={}",
                PathBuf::from(openssl_lib_dir).display()
            );
        }
    }

    // Build the lib. This is copied from its CMakeLists.txt.
    let mut builder = cc::Build::new();

    #[cfg(target_endian = "big")]
    builder.define("WORDS_BIGENDIAN", "");

    builder
        .file(srcdir.join("authenticode.c"))
        .file(srcdir.join("helper.c"))
        .file(srcdir.join("structs.c"))
        .file(srcdir.join("countersignature.c"))
        .file(srcdir.join("certificate.c"))
        .include(libdir.join("include"));
    if let Some(include_dir) = openssl_include_dir {
        builder.include(include_dir);
    }
    builder.compile("authenticode-parser");

    // Link to the built library, and to the openssl dependency
    if target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=dylib=libcrypto");

        println!("cargo:rustc-link-lib=dylib=user32");
        println!("cargo:rustc-link-lib=dylib=crypt32");
    } else {
        println!("cargo:rustc-link-lib=dylib=crypto");
    }

    #[cfg(feature = "bindgen")]
    generate_bindings(&libdir);
}

#[cfg(feature = "bindgen")]
fn generate_bindings(libdir: &std::path::Path) {
    // Generate bindings using bindgen.
    // If https://github.com/avast/authenticode-parser/pull/12 is fixed, this could be removed :(
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
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
