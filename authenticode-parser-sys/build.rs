use std::path::PathBuf;

fn main() {
    let libdir = PathBuf::from("authenticode-parser")
        .canonicalize()
        .expect("cannot canonicalize path to submodule");

    let build_dest = cmake::build("authenticode-parser");

    println!(
        "cargo:rustc-link-search=native={}/lib",
        build_dest.display()
    );
    println!("cargo:rustc-link-lib=static=authenticode");
    // FIXME: handle other OSes and other type of links
    println!("cargo:rustc-link-lib=crypto");

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
