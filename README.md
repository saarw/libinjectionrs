# libinjectionrs

A vibe port (AI translation without manually reviewing much of the code) of the libinjection library from C to memory-safe Rust. Libinjection is a library for SQL injection and XSS attack detection in strings. The port was done with an original plan created with GPT-5 and then mostly executed with Claude Code. 

## Features
- SQL injection detection with fingerprinting
- XSS detection with context awareness
- Minimal heap allocations using `SmallVec`

## Quality controls
- While the AI did all of the coding work, its process was supervised by a human and most of its outputs required additional correction prompts.
- All the test files for the C library are run by the Rust library and pass.
- Differential fuzz testing has been run without revealing differences between C and Rust for over an hour for both SQL injection and XSS inputs.
- Linting has been configured both to deny unsafe code and many conditions that could result in panics in the library, excluding slice indexing which could theoretically still panic (tests and debug tools still allow panics).

## Project Structure
```text
libinjectionrs/
├── benches/                    # Performance benchmarks
├── comparison-bin/             # Tools for comparing Rust vs C behavior
├── docs/                       # Architecture and porting documentation
├── ffi-harness/               # C FFI testing harness
├── fuzz/                      # Fuzzing targets and corpora
├── libinjection-c/            # Git submodule with original C library
├── libinjection-debug/        # Debug tools for comparing implementations
├── libinjectionrs/            # Main Rust library source code
└── scripts/                   # Build and corpus generation scripts
```

## Linting
```cargo clippy --workspace --all-targets -- -A warnings```

## Development

To get started with development, first fetch the git submodule containing the original C library:

```bash
git submodule update --init --recursive
```

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

Licensed under the BSD 3-Clause License ([LICENSE](LICENSE) or <https://opensource.org/licenses/BSD-3-Clause>).

This project is a Rust port of [libinjection](https://github.com/client9/libinjection), which is also licensed under the BSD 3-Clause License.