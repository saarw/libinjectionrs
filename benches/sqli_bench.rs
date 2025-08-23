use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libinjectionrs::detect_sqli;

fn bench_sqli_simple(c: &mut Criterion) {
    let test_cases = vec![
        "SELECT * FROM users WHERE id = 1",
        "1' OR '1'='1",
        "1 UNION SELECT password FROM users",
        "'; DROP TABLE users; --",
        "SELECT * FROM products WHERE price < 100",
        "admin'--",
        "1' AND SLEEP(5)--",
        "' OR 1=1 UNION SELECT table_name FROM information_schema.tables--",
    ];

    c.bench_function("sqli_detection", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(detect_sqli(case.as_bytes()));
            }
        })
    });
}

fn bench_sqli_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqli_individual");
    
    let test_cases = vec![
        ("simple_select", "SELECT * FROM users WHERE id = 1"),
        ("union_injection", "1 UNION SELECT password FROM users"),
        ("boolean_injection", "1' OR '1'='1"),
        ("comment_injection", "admin'--"),
        ("time_based", "1' AND SLEEP(5)--"),
        ("safe_query", "SELECT * FROM products WHERE price < 100"),
    ];

    for (name, input) in test_cases {
        group.bench_function(name, |b| {
            b.iter(|| black_box(detect_sqli(black_box(input.as_bytes()))))
        });
    }
    
    group.finish();
}

fn bench_sqli_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sqli_input_sizes");
    
    let base_injection = "1' OR '1'='1";
    let sizes = vec![10, 50, 100, 500, 1000, 5000];
    
    for size in sizes {
        let mut input = base_injection.to_string();
        while input.len() < size {
            input.push_str(" AND col='val'");
        }
        input.truncate(size);
        
        group.bench_function(format!("size_{}", size), |b| {
            b.iter(|| black_box(detect_sqli(black_box(input.as_bytes()))))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_sqli_simple, bench_sqli_individual, bench_sqli_sizes);
criterion_main!(benches);