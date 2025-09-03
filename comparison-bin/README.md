# Comparison Binary

This directory contains a comparison tool that validates the Rust implementation of libinjection against the original C implementation.

## Purpose

The comparison binary serves as a testing and validation tool to ensure that the Rust port (`libinjectionrs`) produces identical results to the original C library (`libinjection-c`). It's essential for maintaining behavioral compatibility during the porting process.

## What it does

- Compares SQL injection detection results between Rust and C implementations
- Compares XSS detection results between Rust and C implementations
- Validates that tokenization and parsing produce identical outputs
- Reports any discrepancies found during comparison testing

## Build Requirements

### Prerequisites

1. The FFI harness must be built first:
   ```bash
   cd ../ffi-harness
   make
   ```

2. Ensure the `libinjection-c` submodule is properly initialized:
   ```bash
   git submodule update --init --recursive
   ```

### Building

```bash
cargo build -p libinjection-comparison
```

### Running Tests

```bash
cargo test -p libinjection-comparison
```

### Running the Comparison Tool

```bash
cargo run -p libinjection-comparison --bin compare -- [options]
```

## Technical Details

The comparison binary uses:

- **FFI bindings**: Generated via `bindgen` from the C library headers
- **Static linking**: Links directly against `libinjection_harness.a` to avoid runtime library loading issues
- **C interop**: Calls the original C functions through FFI to compare results

## Build Script

The `build.rs` script:
1. Generates Rust bindings from `../ffi-harness/harness.h`
2. Links the static library directly by path to ensure static linking
3. Sets up proper library search paths

## Troubleshooting

If you encounter linking errors:
1. Ensure the FFI harness is built: `cd ../ffi-harness && make`
2. Clean and rebuild: `cargo clean -p libinjection-comparison && cargo build -p libinjection-comparison`
3. Check that `../ffi-harness/lib/libinjection_harness.a` exists