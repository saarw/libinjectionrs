use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let ffi_harness_dir = PathBuf::from(&manifest_dir).parent().unwrap().join("ffi-harness");
    let obj_dir = ffi_harness_dir.join("obj");
    
    // Link object files directly instead of the archive
    let object_files = [
        "libinjection_sqli.o",
        "libinjection_xss.o", 
        "libinjection_html5.o",
        "harness.o"
    ];
    
    // Verify all object files exist
    for obj_file in &object_files {
        let obj_path = obj_dir.join(obj_file);
        if !obj_path.exists() {
            panic!("Object file not found: {}", obj_path.display());
        }
        println!("cargo:rustc-link-arg={}", obj_path.display());
    }
    
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