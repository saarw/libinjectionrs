#![no_main]
use libfuzzer_sys::fuzz_target;
use libinjectionrs::detect_sqli;

fuzz_target!(|data: &[u8]| {
    // Fuzz the SQL injection detector with arbitrary input
    let _ = detect_sqli(data);
});