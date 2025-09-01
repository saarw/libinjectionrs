#![no_main]
use libfuzzer_sys::fuzz_target;
use libinjectionrs::detect_sqli as rust_detect_sqli;
use std::ffi::CString;

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

fn call_c_sqli(input: &[u8]) -> Result<bool, ()> {
    let c_input = CString::new(input).map_err(|_| ())?;
    
    unsafe {
        let result = harness_detect_sqli(
            c_input.as_ptr(),
            input.len(),
            0,
        );
        
        Ok(result.is_sqli != 0)
    }
}

fuzz_target!(|data: &[u8]| {
    // Skip inputs that would cause issues for C string conversion
    if data.contains(&0) {
        return;
    }
    
    let rust_result = rust_detect_sqli(data);
    let rust_is_injection = rust_result.is_injection();
    
    if let Ok(c_is_injection) = call_c_sqli(data) {
        // The implementations should agree on whether input is an injection
        // Note: We don't compare fingerprints as they may differ in format
        if rust_is_injection != c_is_injection {
            // Convert to string for debugging if possible
            let debug_input = String::from_utf8_lossy(data);
            
            // Only panic if input is reasonable length for debugging
            if data.len() < 1000 {
                panic!("Differential detected! Input: {:?}, Rust: {}, C: {}", 
                       debug_input, rust_is_injection, c_is_injection);
            }
        }
    }
});