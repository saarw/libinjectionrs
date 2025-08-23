# Fuzzing Targets

This directory contains fuzzing targets for libinjectionrs using cargo-fuzz.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Available Targets

- `fuzz_sqli` - Fuzz SQL injection detection
- `fuzz_xss` - Fuzz XSS detection  
- `fuzz_differential_sqli` - Differential fuzzing comparing Rust vs C SQL injection detection
- `fuzz_differential_xss` - Differential fuzzing comparing Rust vs C XSS detection

## Running Fuzz Tests

From the root project directory:

```bash
# Fuzz SQL injection detection
cargo fuzz run fuzz_sqli

# Fuzz XSS detection  
cargo fuzz run fuzz_xss

# Differential fuzzing for SQL injection
cargo fuzz run fuzz_differential_sqli

# Differential fuzzing for XSS
cargo fuzz run fuzz_differential_xss
```

## Building the C Library

Before running differential fuzzing targets, ensure the C library is built:

```bash
cd ffi-harness && make
```

The differential fuzzing targets will detect discrepancies between the Rust and C implementations and panic with debugging information when differences are found.