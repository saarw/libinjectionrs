# libinjectionrs

A vibe-ported (AI-assisted translation) of the libinjection library for SQL injection and XSS detection from C to memory-safe Rust.

## Features

- SQL injection detection with fingerprinting
- XSS detection with context awareness
- Zero-copy parsing
- `no_std` support with optional `alloc`
- Minimal heap allocations using `SmallVec`

## Linting
Clippy has been configured to deny unsafe code and many conditions that may result in panics (but still allows indexing into a slice to match the C code). Run clippy with warnings ignored ```cargo clippy --workspace --all-targets -- -A warnings```

## Usage

```rust
use libinjectionrs::{detect_sqli, detect_xss};

// SQL injection detection
let input = b"1' OR '1'='1";
let result = detect_sqli(input);
if result.is_injection() {
    println!("SQL injection detected: {:?}", result.fingerprint);
}

// XSS detection
let input = b"<script>alert('xss')</script>";
let result = detect_xss(input);
if result.is_injection() {
    println!("XSS detected");
}
```

## License

Licensed under either of:
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.