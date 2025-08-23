use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_dir = PathBuf::from(&manifest_dir).parent().unwrap().join("ffi-harness").join("lib");
    
    // Tell cargo to look for libraries in the specified directory
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    
    // Force static linking by specifying the full path to the static library
    let static_lib_path = lib_dir.join("libinjection_harness.a");
    println!("cargo:rustc-link-arg={}", static_lib_path.display());
    
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=../ffi-harness/harness.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("../ffi-harness/harness.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}