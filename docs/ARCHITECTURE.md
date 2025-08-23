# libinjectionrs Architecture

This document describes the mapping from the C libinjection library to the Rust implementation.

## Overview

The Rust port maintains behavioral compatibility with the original C implementation while providing a safe, idiomatic Rust API. The architecture focuses on zero-copy parsing, minimal allocations, and optional `no_std` support.

## Type Mappings

### Core Types

| C Type | Rust Type | Notes |
|--------|-----------|-------|
| `const char*` + `size_t` | `&[u8]` | Input strings as byte slices |
| `char fingerprint[8]` | `Fingerprint` newtype | Stack-allocated fingerprint |
| `enum sqli_flags` | `bitflags::SqliFlags` | Type-safe flag handling |
| `struct libinjection_sqli_token` | `Token` struct | Rust struct with enum variants |
| `struct libinjection_sqli_state` | `SqliState<'a>` (internal) | Lifetime-bound state |
| `int` (return values) | `Result<T, Error>` or enums | Explicit error handling |

### API Mapping

#### SQL Injection Detection

**C API:**
```c
int libinjection_sqli(const char *s, size_t slen, char fingerprint[]);
void libinjection_sqli_init(struct libinjection_sqli_state *sf, const char *s, size_t len, int flags);
int libinjection_is_sqli(struct libinjection_sqli_state *sql_state);
```

**Rust API:**
```rust
pub fn detect_sqli(input: &[u8]) -> SqliResult;

pub struct SqliDetector { ... }
impl SqliDetector {
    pub fn new() -> Self;
    pub fn with_flags(self, flags: SqliFlags) -> Self;
    pub fn detect(&self, input: &[u8]) -> SqliResult;
}
```

#### XSS Detection

**C API:**
```c
int libinjection_xss(const char *s, size_t slen);
int libinjection_is_xss(const char *s, size_t len, int flags);
```

**Rust API:**
```rust
pub fn detect_xss(input: &[u8]) -> XssResult;

pub struct XssDetector { ... }
impl XssDetector {
    pub fn new() -> Self;
    pub fn with_flags(self, flags: u32) -> Self;
    pub fn detect(&self, input: &[u8]) -> XssResult;
}
```

## Key Design Decisions

### 1. Zero-Copy Parsing
- Input remains as `&[u8]` throughout parsing
- Tokens store positions and lengths rather than copying strings
- String views are created on-demand

### 2. Memory Management
- Stack allocation preferred (fixed-size arrays for fingerprints)
- Optional `SmallVec` for variable-length token storage
- No heap allocation in hot paths when `smallvec` feature is disabled

### 3. Error Handling
- `Result<T, Error>` for fallible operations
- Enums (`SqliResult`, `XssResult`) for detection results
- No panics in normal operation

### 4. Feature Flags
- `std` (default): Standard library support
- `smallvec`: Optimize small allocations
- `no_std`: Core-only operation with optional `alloc`

### 5. Token Representation

**C Structure:**
```c
struct libinjection_sqli_token {
    size_t pos;
    size_t len;
    int count;
    char type;
    char str_open;
    char str_close;
    char val[32];
};
```

**Rust Structure:**
```rust
pub struct Token {
    pub pos: usize,
    pub len: usize,
    pub token_type: TokenType,  // Enum instead of char
    pub count: i32,
    pub str_open: Option<char>,  // Optional instead of sentinel
    pub str_close: Option<char>,
    pub value: TokenValue,        // Enum for different value types
}
```

### 6. State Management

The C library uses a mutable state structure that gets passed around. In Rust:
- Internal state (`SqliState`, `XssState`) is encapsulated
- Public API uses builder pattern (`SqliDetector`, `XssDetector`)
- Lifetime bounds ensure memory safety

### 7. Callback System

**C Approach:**
Function pointers for custom lookup functions.

**Rust Approach:**
```rust
impl SqliDetector {
    pub fn with_lookup<F>(self, lookup: F) -> Self
    where F: Fn(&str) -> Option<TokenType> + 'static
}
```

Uses trait bounds and closures for type safety and flexibility.

## Performance Considerations

1. **Branch Prediction**: Enum variants for tokens enable better branch prediction than char comparisons
2. **SIMD Potential**: Byte slice operations can leverage SIMD when available
3. **Cache Locality**: Tokens stored contiguously in vectors
4. **Minimal Allocations**: Stack-based storage for common cases

## Safety Guarantees

1. **Memory Safety**: No unsafe code in the public API
2. **Thread Safety**: Detectors are `Send` and `Sync`
3. **Panic Safety**: No panics except in cases of programmer error
4. **Input Validation**: All inputs are validated, malformed UTF-8 handled gracefully

## Testing Strategy

1. **Fuzzing**: Property-based testing with arbitrary inputs
2. **Conformance**: Test vectors from original C implementation
3. **Benchmarks**: Performance regression tests
4. **Miri**: Undefined behavior detection
5. **Cross-platform**: CI testing on multiple architectures

## Future Enhancements

1. **WASM Support**: Compile to WebAssembly for browser-based detection
2. **Async Support**: Non-blocking detection for large inputs
3. **Custom Allocators**: Support for custom memory allocators
4. **Serialization**: Optional serde support for results
5. **C API Compatibility Layer**: Optional C-compatible API for drop-in replacement