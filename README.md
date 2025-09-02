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

## Fuzzing
Scripts create fuzz corpuses:
  What the script does:

  1. SQLi corpus: Extracts 50 SQL injection test cases from test-sqli-*.txt
  files
  2. XSS corpus: Extracts 63 HTML/XSS test cases from test-html5-*.txt files

  3. Deduplication: Uses SHA1 hashes to avoid duplicate entries
  4. Proper naming: Prefixes seeded files with seed_sqli_ or seed_xss_

  Usage:

  ./scripts/seed_fuzz_corpus.sh sqli    # Seed SQLi corpus only
  ./scripts/seed_fuzz_corpus.sh xss     # Seed XSS corpus only  
  ./scripts/seed_fuzz_corpus.sh all     # Seed both corpora

## License

Licensed under the BSD 3-Clause License ([LICENSE](LICENSE) or https://opensource.org/licenses/BSD-3-Clause).

This project is a Rust port of [libinjection](https://github.com/client9/libinjection), which is also licensed under the BSD 3-Clause License.