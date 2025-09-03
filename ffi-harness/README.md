# FFI Harness

This directory contains a C library harness that wraps the original libinjection C implementation for use with the Rust comparison tools.

## Purpose

The FFI harness provides a stable C API that can be called from Rust via FFI (Foreign Function Interface). This allows the Rust port to compare its results directly against the original C implementation to ensure behavioral compatibility.

## What it provides

- **C wrapper functions**: Simplified C API around the original libinjection functions
- **Static library**: `libinjection_harness.a` for static linking with Rust
- **Shared library**: `libinjection_harness.so` for dynamic linking (optional)
- **Header file**: `harness.h` with function declarations for bindgen

## Build Requirements

### Prerequisites

1. GCC or compatible C compiler
2. Make
3. The `libinjection-c` submodule must be initialized:
   ```bash
   cd ..
   git submodule update --init --recursive
   ```

### Building

```bash
make
```

This will:
1. Compile the original libinjection C source files
2. Compile the harness wrapper
3. Create both static (`libinjection_harness.a`) and shared (`libinjection_harness.so`) libraries in `lib/`

### Cleaning

```bash
make clean
```

## Output Files

After building, you'll find:

```
lib/
├── libinjection_harness.a    # Static library (used by Rust)
└── libinjection_harness.so   # Shared library

obj/
├── libinjection_sqli.o       # Compiled SQL injection detection
├── libinjection_xss.o        # Compiled XSS detection  
├── libinjection_html5.o      # Compiled HTML5 parser
└── harness.o                 # Compiled harness wrapper
```

## API

The harness provides simplified wrapper functions around the original libinjection API. See `harness.h` for the complete API, which includes:

- SQL injection detection functions
- XSS detection functions
- Tokenization and parsing utilities
- Result structures compatible with Rust FFI

## Usage

This library is primarily used by:
- `../comparison-bin/` - For comparing Rust vs C implementations
- `../libinjection-debug/` - For debugging differences between implementations

## Makefile Targets

- `make` or `make all` - Build both static and shared libraries
- `make clean` - Remove all build artifacts
- `make lib/libinjection_harness.a` - Build only the static library
- `make lib/libinjection_harness.so` - Build only the shared library

## Compiler Flags

The Makefile uses:
- `-fPIC` - Position Independent Code (required for shared libraries)
- `-O3` - Optimization level 3
- `-g` - Debug information
- `-fno-omit-frame-pointer` - Keep frame pointers for debugging
- `-DLIBINJECTION_VERSION="3.10.0"` - Version definition