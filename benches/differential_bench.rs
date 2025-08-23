use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libinjectionrs::{detect_sqli as rust_detect_sqli, detect_xss as rust_detect_xss};
use std::ffi::CString;

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

fn call_c_sqli(input: &str) -> bool {
    let c_input = CString::new(input).unwrap();
    
    unsafe {
        let result = harness_detect_sqli(
            c_input.as_ptr(),
            input.len(),
            0,
        );
        
        result.is_sqli != 0
    }
}

fn call_c_xss(input: &str) -> bool {
    let c_input = CString::new(input).unwrap();
    
    unsafe {
        let result = harness_detect_xss(
            c_input.as_ptr(),
            input.len(),
            0,
        );
        
        result.is_xss != 0
    }
}

fn bench_rust_vs_c_sqli(c: &mut Criterion) {
    let test_cases = vec![
        "SELECT * FROM users WHERE id = 1",
        "1' OR '1'='1",
        "1 UNION SELECT password FROM users",
        "'; DROP TABLE users; --",
        "admin'--",
    ];

    let mut group = c.benchmark_group("sqli_rust_vs_c");
    
    group.bench_function("rust_sqli", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(rust_detect_sqli(black_box(case.as_bytes())));
            }
        })
    });
    
    group.bench_function("c_sqli", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(call_c_sqli(black_box(case)));
            }
        })
    });
    
    group.finish();
}

fn bench_rust_vs_c_xss(c: &mut Criterion) {
    let test_cases = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)></iframe>",
        "javascript:alert('xss')",
        "Hello world",
    ];

    let mut group = c.benchmark_group("xss_rust_vs_c");
    
    group.bench_function("rust_xss", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(rust_detect_xss(black_box(case.as_bytes())));
            }
        })
    });
    
    group.bench_function("c_xss", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(call_c_xss(black_box(case)));
            }
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_rust_vs_c_sqli, bench_rust_vs_c_xss);
criterion_main!(benches);