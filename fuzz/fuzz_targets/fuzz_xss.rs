#![no_main]
use libfuzzer_sys::fuzz_target;
use libinjectionrs::detect_xss;

fuzz_target!(|data: &[u8]| {
    // Fuzz the XSS detector with arbitrary input
    let _ = detect_xss(data);
});