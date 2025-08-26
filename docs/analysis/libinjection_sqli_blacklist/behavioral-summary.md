# Behavioral Summary - libinjection_sqli_blacklist

## Executive Summary

`libinjection_sqli_blacklist` is a pattern-matching function that determines whether a SQL fingerprint corresponds to a known SQL injection attack pattern. It serves as the core detection mechanism in the libinjection library, converting fingerprint formats and performing database lookups to identify malicious SQL patterns.

## Core Behavior

### Primary Function
- **Input**: SQL state structure containing a tokenized SQL fingerprint
- **Output**: Boolean determination of whether fingerprint matches known SQLi patterns
- **Side Effect**: Sets debug reason codes for failure analysis

### Algorithm Overview
1. Validates fingerprint length (must be ≥ 1)
2. Converts fingerprint from v0 to v1 format (adds '0' prefix, uppercases)
3. Performs binary search in fingerprint database
4. Returns TRUE if pattern found, FALSE otherwise

## Key Behavioral Characteristics

### Deterministic Operation
- Same input always produces same output
- No randomization or time-dependent behavior
- Predictable execution paths based on input characteristics

### Error Handling Philosophy
- **Fail-fast**: Returns FALSE immediately for invalid inputs
- **Debugging support**: Provides specific line numbers for failure diagnosis
- **No exceptions**: Uses C-style boolean return values

### Performance Profile
- **Time Complexity**: O(log n) where n is database size
- **Space Complexity**: O(1) with fixed 8-byte local buffer
- **Cache Efficiency**: Good locality for both conversion and lookup operations

## Input/Output Specifications

### Input Requirements
```c
struct libinjection_sqli_state *sql_state
```
- Must contain valid, null-terminated fingerprint string
- Fingerprint length typically 1-5 characters
- Structure must be non-null and properly initialized

### Output Guarantees
- **Return Value**: `TRUE` (SQLi detected) or `FALSE` (benign/invalid)
- **State Modification**: Sets `sql_state->reason` on failure paths
- **Memory Safety**: No buffer overflows or memory corruption

### Error Conditions
1. **Empty Fingerprint**: `strlen(fingerprint) < 1` → FALSE, reason = 1987
2. **Pattern Not Found**: Valid fingerprint but no database match → FALSE, reason = 2017

## Critical Dependencies

### Internal Dependencies
- **is_keyword()**: Binary search function for database lookup
- **FORMAT_FINGERPRINT constant**: Database marker for SQLi patterns
- **strlen()**: Standard library string length calculation

### External Dependencies
- **Fingerprint Database**: Precompiled patterns with TYPE_FINGERPRINT markers
- **Prior Processing**: Requires valid fingerprint from tokenization/folding phases
- **Memory**: Stack space for 8-byte conversion buffer

## Version Compatibility

### Format Evolution Support
- **v0 Format**: Original mixed-case fingerprints (≤ 5 characters)
- **v1 Format**: '0' prefix + uppercase fingerprints (backward compatible)
- **Conversion Logic**: Automatic translation maintains compatibility

### Database Compatibility
- Designed to work with existing fingerprint databases
- TYPE_FINGERPRINT = 'F' (ASCII 70) marker system
- Binary search compatible with sorted database structure

## Security Properties

### Memory Safety
- **Buffer Bounds**: All array accesses within allocated bounds
- **Stack Protection**: 8-byte minimum for compiler stack protection
- **No Dynamic Memory**: Eliminates heap-related vulnerabilities

### Attack Resistance
- **Input Validation**: Rejects malformed or invalid fingerprints
- **Bounds Checking**: Prevents buffer overflow attacks
- **Deterministic**: No timing-based information leakage

## Integration Context

### Role in Detection Pipeline
```
SQL Input → Tokenize → Fold → Fingerprint → [BLACKLIST] → Final Decision
```

### Caller Relationships
- **Called by**: `libinjection_sqli_check_fingerprint()`
- **Depends on**: Prior tokenization and folding phases
- **Collaborates with**: `libinjection_sqli_not_whitelist()` for final determination

## Edge Cases and Limitations

### Known Edge Cases
1. **Empty String**: Handled explicitly with early return
2. **Maximum Length**: Implicit bounds from fingerprint generation
3. **Invalid Characters**: Handled by database lookup failure

### Functional Limitations
- **Database Dependent**: Effectiveness limited by fingerprint database completeness
- **Pattern Based**: Cannot detect novel attack patterns not in database
- **Format Specific**: Requires specific fingerprint format from prior stages

### Performance Limitations
- **Database Size**: Lookup performance scales logarithmically with database size
- **Sequential Conversion**: Format conversion has linear overhead
- **Memory Bandwidth**: Limited by cache efficiency of database access

## Testing Implications

### Critical Test Cases
1. **Valid SQLi Patterns**: Known fingerprints should return TRUE
2. **Benign Patterns**: Non-malicious fingerprints should return FALSE
3. **Edge Conditions**: Empty strings, maximum lengths, boundary values
4. **Format Compatibility**: v0 fingerprints should work correctly

### Invariant Testing
- **Memory Safety**: No buffer overflows under any input
- **Determinism**: Identical inputs produce identical outputs
- **State Consistency**: sql_state remains valid after function execution

## Rust Porting Considerations

### Direct Translation Opportunities
- Algorithm logic can be ported directly
- Binary search pattern suitable for Rust standard library
- Error handling maps well to Result<bool, Error> pattern

### Rust-Specific Improvements
- **Memory Safety**: Compile-time guarantees eliminate buffer overflow risks
- **String Handling**: UTF-8 aware string processing with proper bounds checking
- **Error Handling**: Rich error types with context information
- **Performance**: Zero-cost abstractions for better optimization opportunities

### API Design Recommendations
```rust
fn is_sqli_blacklist(fingerprint: &str) -> Result<bool, BlacklistError>
```
- Immutable string reference eliminates mutation concerns
- Result type provides rich error information
- No need for separate reason field with proper error types