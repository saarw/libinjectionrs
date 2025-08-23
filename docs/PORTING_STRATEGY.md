# libinjectionrs Porting Strategy

## Executive Summary

We will use a **hybrid approach**: begin with careful transliteration of the C code to maintain behavioral equivalence, then progressively refactor to idiomatic Rust while maintaining comprehensive test coverage.

## Recommended Approach: Transliteration First, Then Refactor

### Phase 2.1: Direct Transliteration (Current)
- Port C code line-by-line maintaining exact control flow
- Preserve all state machines and parsing logic
- Keep internal function structure similar to C
- Focus on correctness over idiomaticity

### Phase 2.2: Test Parity
- Import all test vectors from C implementation
- Create differential testing harness against C library
- Achieve 100% behavioral equivalence

### Phase 2.3: Progressive Refactoring
- Replace unsafe patterns with safe Rust idioms
- Optimize hot paths with Rust-specific features
- Maintain test coverage throughout

## C to Rust Mapping Guide

### Core Type Mappings

| C Pattern | Rust Translation | Notes |
|-----------|------------------|-------|
| `char *s + size_t len` | `&[u8]` or `&str` | Use slices for safety |
| `char buffer[N]` | `[u8; N]` or `ArrayVec<u8, N>` | Stack allocation preferred |
| `int` flags | `bitflags!` struct | Type-safe flag handling |
| `enum` as integers | Rust `enum` with discriminants | Preserve C values for compatibility |
| Function pointers | `fn` pointers or trait objects | Use closures where appropriate |
| `void *userdata` | Generic type parameter `T` | Type safety via generics |

### Pointer Arithmetic Translation

| C Pattern | Rust Translation |
|-----------|------------------|
| `ptr++` | `slice = &slice[1..]` |
| `ptr += n` | `slice = &slice[n..]` |
| `*ptr` | `slice[0]` or `slice.first()` |
| `ptr[i]` | `slice[i]` or `slice.get(i)` |
| `ptr - base` | `ptr_pos - base_pos` (track indices) |
| `ptr < end` | `pos < slice.len()` |

### Buffer Handling

| C Pattern | Rust Translation |
|-----------|------------------|
| Static buffers | `const` arrays or `lazy_static!` |
| Dynamic allocation | `Vec<T>` or `Box<[T]>` |
| String building | `String` or `SmallString` |
| Temporary buffers | Stack arrays or `SmallVec` |

### Character Classes and Tables

| C Pattern | Rust Translation |
|-----------|------------------|
| `isdigit()`, `isalpha()` | `char::is_ascii_digit()`, etc. |
| Character lookup tables | `const` arrays or match expressions |
| Function pointer tables | `const` array of function pointers |
| String tables | `const` array of `&'static str` |

### State Machine Patterns

```rust
// C: switch-based state machine
// Rust: enum-based state machine

enum State {
    Initial,
    InString { quote: u8 },
    InComment,
    // ...
}

impl State {
    fn transition(self, input: u8) -> Self {
        match (self, input) {
            (State::Initial, b'"') => State::InString { quote: b'"' },
            // ...
        }
    }
}
```

### Error Handling

| C Pattern | Rust Translation |
|-----------|------------------|
| Return -1 or NULL | `Result<T, Error>` |
| errno-style errors | Error enum variants |
| Assertions | `debug_assert!` or `Result` |
| Silent truncation | Explicit handling or `Result` |

## Internal vs Public Functions

### Public API (from C headers)
These functions will remain public in Rust:

**Core Detection:**
- `libinjection_sqli()` → `detect_sqli()`
- `libinjection_xss()` → `detect_xss()`
- `libinjection_version()` → `version()`

**Advanced SQLi API:**
- `libinjection_sqli_init()` → `SqliDetector::new()`
- `libinjection_is_sqli()` → `SqliDetector::detect()`
- `libinjection_sqli_fingerprint()` → `SqliDetector::fingerprint()`
- `libinjection_sqli_reset()` → `SqliDetector::reset()`
- `libinjection_sqli_callback()` → `SqliDetector::with_callback()`

**Token Access:**
- `libinjection_sqli_tokenize()` → `SqliTokenizer` (iterator)
- `libinjection_sqli_fold()` → Internal (private)
- `libinjection_sqli_get_token()` → Token accessor methods

### Internal Functions (will be private)
These C functions will become private methods or module-private functions:

**Parsing Functions:**
- `parse_*()` functions → Private methods in tokenizer
- `flag2delim()` → Private helper
- `is_backslash_escaped()` → Private helper

**Lookup Functions:**
- `libinjection_sqli_lookup_word()` → Private, unless custom lookup needed
- Binary tree lookups → Private implementation detail

**Fingerprint Analysis:**
- `libinjection_sqli_blacklist()` → Private method
- `libinjection_sqli_not_whitelist()` → Private method

## Implementation Priority

1. **Critical Path First**
   - SQL tokenizer (`parse_*` functions)
   - Token folding logic
   - Fingerprint generation
   - Blacklist checking

2. **Secondary Features**
   - XSS detection
   - Custom callbacks
   - Advanced configuration

3. **Optimizations**
   - SIMD for string scanning
   - Lookup table optimization
   - Memory pool for tokens

## Translation Rules

### Rule 1: Preserve Magic Numbers
Keep all magic constants, buffer sizes, and limits identical to C:
```rust
const LIBINJECTION_SQLI_MAX_TOKENS: usize = 5;
const LIBINJECTION_SQLI_TOKEN_SIZE: usize = 32;
```

### Rule 2: Maintain State Machine Structure
Translate switch statements to match expressions but preserve all state transitions:
```rust
match current_state {
    // Preserve exact same transitions as C
}
```

### Rule 3: Character-by-Character Processing
Keep the same byte-by-byte processing for compatibility:
```rust
while pos < input.len() {
    let ch = input[pos];
    // Process exactly as C does
}
```

### Rule 4: Preserve Lookup Tables
Translate C lookup tables directly:
```rust
const CHAR_PARSE_MAP: [ParseFn; 256] = [
    parse_white,  // 0
    parse_white,  // 1
    // ... exact same mapping
];
```

### Rule 5: Unsafe Only When Necessary
Use unsafe only for:
- FFI boundaries (if providing C API)
- Performance-critical lookups (with bounds checking in debug)
- Never for public API

## Testing Strategy

### Differential Testing
```rust
#[test]
fn differential_test(input: &[u8]) {
    let rust_result = detect_sqli(input);
    let c_result = unsafe { libinjection_sqli_ctest(input) };
    assert_eq!(rust_result, c_result);
}
```

### Fuzzing
- Use cargo-fuzz with AFL
- Differential fuzzing against C library
- Property-based testing with proptest

### Benchmarking
- Criterion.rs for micro-benchmarks
- Compare against C implementation
- Track performance regressions

## Success Criteria

1. **Behavioral Equivalence**
   - 100% match on all C test vectors
   - Identical fingerprints for all inputs
   - Same true/false positive rates

2. **Performance**
   - Within 10% of C implementation initially
   - Target: faster than C after optimization

3. **Safety**
   - No unsafe in public API
   - All unsafe blocks documented
   - Miri-clean

4. **Maintainability**
   - Clear mapping to C code
   - Comprehensive documentation
   - Easy to verify correctness

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Subtle behavioral differences | Extensive differential testing |
| Performance regression | Continuous benchmarking |
| Integer overflow differences | Explicit wrapping arithmetic |
| Character encoding issues | Byte-oriented processing |
| Lookup table mismatches | Direct translation with tests |

## Next Steps

1. Begin with `libinjection_sqli_tokenize()` transliteration
2. Create test harness with C test vectors
3. Implement token folding algorithm
4. Add fingerprint generation
5. Complete blacklist/whitelist logic
6. Verify with differential testing
7. Begin progressive refactoring

This approach ensures we maintain exact compatibility while setting up for future optimization.