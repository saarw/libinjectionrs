use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libinjectionrs::detect_xss;

fn bench_xss_simple(c: &mut Criterion) {
    let test_cases = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)></iframe>",
        "javascript:alert('xss')",
        "<div onclick=alert(1)>click</div>",
        "Hello world",
        "<p>Safe content</p>",
        "data:text/html,<script>alert(1)</script>",
    ];

    c.bench_function("xss_detection", |b| {
        b.iter(|| {
            for case in &test_cases {
                black_box(detect_xss(case.as_bytes()));
            }
        })
    });
}

fn bench_xss_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("xss_individual");
    
    let test_cases = vec![
        ("script_tag", "<script>alert('xss')</script>"),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("iframe_js", "<iframe src=javascript:alert(1)></iframe>"),
        ("javascript_url", "javascript:alert('xss')"),
        ("event_handler", "<div onclick=alert(1)>click</div>"),
        ("safe_text", "Hello world"),
        ("safe_html", "<p>Safe content</p>"),
        ("data_url", "data:text/html,<script>alert(1)</script>"),
    ];

    for (name, input) in test_cases {
        group.bench_function(name, |b| {
            b.iter(|| black_box(detect_xss(black_box(input.as_bytes()))))
        });
    }
    
    group.finish();
}

fn bench_xss_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("xss_input_sizes");
    
    let base_xss = "<script>alert('xss')</script>";
    let sizes = vec![10, 50, 100, 500, 1000, 5000];
    
    for size in sizes {
        let mut input = base_xss.to_string();
        while input.len() < size {
            input.push_str("<div>content</div>");
        }
        input.truncate(size);
        
        group.bench_function(format!("size_{}", size), |b| {
            b.iter(|| black_box(detect_xss(black_box(input.as_bytes()))))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_xss_simple, bench_xss_individual, bench_xss_sizes);
criterion_main!(benches);