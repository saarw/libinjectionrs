# Benchmarks

This directory contains Criterion benchmarks for libinjectionrs performance testing.

## Available Benchmarks

- `sqli_bench` - SQL injection detection performance
- `xss_bench` - XSS detection performance
- `differential_bench` - Performance comparison between Rust and C implementations

## Running Benchmarks

From the root project directory:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench sqli_bench
cargo bench --bench xss_bench  
cargo bench --bench differential_bench
```

## Building the C Library

Before running differential benchmarks, ensure the C library is built:

```bash
cd ffi-harness && make
```

## Output

Benchmark results are saved as HTML reports in `target/criterion/` for detailed analysis and comparison over time.