# libinjection-debug

A comprehensive debugging tool for libinjection tokenization analysis and C/Rust comparison.

## Features

- **Step-by-step tokenization analysis** - See exactly how input is parsed character by character
- **C vs Rust comparison** - Detect differentials between implementations
- **Multiple input formats** - String, hex, base64, file input
- **Interactive debugging** - Step through tokenization manually
- **Built-in test cases** - Common patterns and known edge cases
- **Multiple output formats** - Text, JSON, CSV export

## Quick Start

```bash
# Build the tool
cd libinjection-debug
cargo build --release

# Build C harness (required for C comparison)
cd c_harness && make

# Basic analysis
./target/release/libinjection-debug "SELECT * FROM users"

# Analyze the problematic fuzzing case
./target/release/libinjection-debug "`n'#'"

# Compare C vs Rust implementations
./target/release/libinjection-debug --compare-c-rust "`n'#'"

# Step-by-step analysis
./target/release/libinjection-debug --step-by-step "' OR '1'='1"

# Run built-in test cases
./target/release/libinjection-debug test
```

## Usage Examples

### Basic Input Analysis

```bash
# Analyze a string
libinjection-debug "SELECT * FROM users WHERE id = 1"

# Analyze hex input
libinjection-debug --hex "27206f7220273127203d202731"

# Analyze from file
libinjection-debug --file suspicious_input.txt
```

### Advanced Debugging

```bash
# Step-by-step with C comparison
libinjection-debug --step-by-step --compare-c-rust "`n'#'"

# Interactive mode
libinjection-debug interactive

# Export as JSON
libinjection-debug --output json "problematic input" > analysis.json

# Trace folding operations
libinjection-debug --trace-folding "complex query"
```

### Batch Analysis

```bash
# Create input file
echo -e "SELECT 1\n' OR '1'='1\n\`n'#'" > inputs.txt

# Batch analyze
libinjection-debug batch inputs.txt
```

## Output Format

### Basic Output
```
=== Input Analysis ===
Original: `n'#'
Bytes: [96, 110, 39, 35, 39]
Hex: 606e272327
Length: 5 bytes
Flags: FLAG_SQL_ANSI

=== Final Tokens ===
Token 0: BAREWORD 'n'#'' (pos=1, len=4)

=== Analysis Results ===
Fingerprint: n
SQL Injection: FALSE
```

### Differential Detection
```
=== C Implementation Comparison ===
C Fingerprint: sos
C SQL Injection: TRUE

❌ DIFFERENTIAL DETECTED
  Fingerprint mismatch:
    Rust: n
    C:    sos
  Detection mismatch:
    Rust: FALSE
    C:    TRUE
```

## Built-in Test Cases

The tool includes several built-in test cases for common scenarios:

- `basic_select` - Simple legitimate SQL
- `classic_injection` - Basic OR-based injection  
- `backtick_hash_case` - The problematic fuzzing case
- `hash_in_quotes` - Hash character handling
- `unclosed_backtick` - Edge case testing

Run specific tests:
```bash
libinjection-debug test backtick
libinjection-debug test classic_injection
```

## Development Workflows

### Investigating Differentials
1. Use `--compare-c-rust` to detect differences
2. Add `--step-by-step` for detailed analysis
3. Use `--diff-only` to see only mismatches
4. Export results with `--output json` for further analysis

### Adding New Test Cases
Edit `src/test_cases.rs` to add new test cases:

```rust
("new_test".to_string(), TestCase {
    input: "test input".to_string(),
    input_desc: "Description".to_string(),
    expected: Some(ExpectedResult {
        fingerprint: "expected".to_string(),
        is_sqli: false,
    }),
    description: "Detailed description".to_string(),
}),
```

### Debugging Tokenization Issues
1. Start with basic analysis: `libinjection-debug "input"`
2. Add step-by-step: `--step-by-step`
3. Compare with C: `--compare-c-rust`
4. Use interactive mode for complex cases: `libinjection-debug interactive`

## Architecture

The tool consists of several components:

- **main.rs** - CLI interface and argument parsing
- **tokenizer_debug.rs** - Core Rust tokenization analysis
- **comparison.rs** - C harness integration
- **formatters.rs** - Output formatting (text, JSON, CSV)
- **test_cases.rs** - Built-in test cases
- **c_harness/** - C tokenization wrapper

## C Harness

The C harness (`c_harness/debug_harness`) provides detailed tokenization information from the original C implementation. It outputs structured data that the Rust tool parses for comparison.

Build the C harness:
```bash
cd c_harness
make
```

Test the C harness directly:
```bash
echo "`n'#'" | ./debug_harness
```

## Integration

### With Existing Tools
The debug tool can be integrated with the existing comparison infrastructure:

```bash
# Use with comparison-bin
comparison-bin/compare | libinjection-debug --hex

# Process fuzzing results
find corpus/ -name "*.input" -exec libinjection-debug --file {} \;
```

### CI Integration
The tool returns appropriate exit codes for automated testing:

```bash
# Will exit with code 1 if differentials are detected
libinjection-debug test --compare-c-rust
```

## Troubleshooting

### C Harness Build Issues
- Ensure `libinjection-c` submodule is initialized
- Check that `LIBINJECTION_VERSION` is defined
- Verify include paths in Makefile

### Missing Dependencies
```bash
# Install Rust dependencies
cargo build

# Install system dependencies (if needed)
# Ubuntu/Debian: apt install build-essential
# macOS: xcode-select --install
```

### Performance Issues
For large inputs or batch analysis:
- Use `--raw-tokens-only` to skip folding analysis
- Disable `--step-by-step` for faster processing
- Use `--diff-only` to see only problematic cases

## Contributing

To add new features:

1. **New output formats**: Add to `formatters.rs`
2. **New analysis modes**: Extend `tokenizer_debug.rs`
3. **New test cases**: Add to `test_cases.rs`
4. **C harness improvements**: Modify `c_harness/debug_harness.c`

The tool is designed to be extensible and maintainable for long-term debugging needs.