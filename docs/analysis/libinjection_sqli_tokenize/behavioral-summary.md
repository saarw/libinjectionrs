# Behavioral Summary - libinjection_sqli_tokenize

## Executive Summary

The `libinjection_sqli_tokenize` function is a streaming SQL tokenizer that extracts exactly one token from an input string, advancing the parsing position for subsequent calls. It serves as the foundation of libinjection's SQL injection detection by converting raw SQL text into a structured token stream.

## Core Function Behavior

### Primary Operation
- **Input**: Parsing state structure containing input string, position, and configuration
- **Output**: Boolean indicating token found + populated token structure
- **Side Effects**: Advances parsing position, updates token counter
- **Streaming**: Designed for repeated calls to tokenize entire input

### Return Value Semantics
- **`TRUE`**: Valid token extracted and available in `sf->current`
- **`FALSE`**: No token found (end of input or empty input)

## Critical Behavioral Properties

### 1. Position Management
- Position (`sf->pos`) monotonically increases or stays the same
- Never reads beyond `sf->slen` due to loop bounds checking
- Position advancement handled by character-specific parser functions

### 2. Token Production
- Exactly zero or one token produced per call
- Token validity indicated by `sf->current->type != CHAR_NULL`
- Token statistics (`sf->stats_tokens`) accurately maintained

### 3. Character Dispatch System
- Uses 256-entry function pointer table (`char_parse_map`) for O(1) character handling
- Each ASCII character maps to specialized parser function
- Parser functions handle token extraction and position advancement

## Key Implementation Details

### Quote Context Handling
Special processing when parsing begins (`pos == 0`) with quote flags set:
- Immediately processes the input as a quoted string
- Uses `flag2delim()` to determine quote character  
- Bypasses normal character-by-character processing

### Main Parsing Loop
Standard tokenization follows this pattern:
1. Check bounds (`pos < slen`)
2. Read character at current position
3. Dispatch to character-specific parser via lookup table
4. Parser updates position and possibly produces token
5. Check if token was produced, return accordingly

## Safety and Reliability Analysis

### Memory Safety
✅ **Safe**: Input buffer access protected by bounds checking  
⚠️ **Assumption**: Parser functions respect buffer bounds (not verified in this function)  
⚠️ **Assumption**: Token value buffer (32 bytes) not overflowed by parsers  
❌ **Unsafe**: No NULL pointer checks on critical parameters

### Error Handling
- **Empty input**: Gracefully returns `FALSE`
- **End of input**: Natural termination when `pos >= slen`
- **Invalid characters**: Handled by character-specific parsers
- **No exceptions**: Pure C implementation with return code semantics

### State Consistency
- Function maintains parsing state integrity
- Failed token extraction doesn't corrupt state
- Position always remains valid for next call

## Integration Points

### Dependencies
- **Parser Functions**: Relies on ~20 character-specific parsers
- **Helper Functions**: `st_clear`, `flag2delim`, `parse_string_core`
- **Lookup Tables**: `char_parse_map` function pointer array
- **Data Structures**: Token and state structure definitions

### Used By
- **`libinjection_sqli_fold()`**: Calls repeatedly to build token sequence
- **Custom Analysis**: Direct usage for token stream inspection
- **Testing/Debugging**: Individual token extraction for analysis

## Critical Assumptions for Rust Port

### Verified Assumptions
1. Input string length is accurate (`sf->slen` matches actual string)
2. Parsing position starts within valid range (`sf->pos <= sf->slen`)
3. Loop bounds checking prevents buffer overruns

### Unverified Assumptions (Require Validation)
1. **NULL Safety**: `sf`, `sf->s`, and `sf->current` are non-null
2. **Parser Contracts**: Character parsers respect position/bounds contracts
3. **Lookup Table**: `char_parse_map` contains valid function pointers
4. **Token Buffer**: Parsers don't overflow 32-byte token value buffer

### Platform Assumptions  
1. `size_t` arithmetic doesn't overflow in typical usage
2. Function pointers in lookup table remain valid
3. Character parsing functions are thread-safe if needed

## Rust Implementation Guidance

### Safety Improvements
- Add explicit NULL checks with `Option` types
- Use bounds-checked slices instead of raw pointers
- Validate parser function contracts with debug assertions
- Consider `Result` type for error propagation instead of boolean returns

### Performance Considerations
- Maintain O(1) character dispatch with function pointer equivalent
- Preserve streaming semantics for efficient large input processing
- Consider zero-copy token extraction where possible

### Error Handling Evolution
- Convert boolean returns to `Result<Option<Token>, Error>`
- Add specific error types for different failure modes
- Provide better diagnostics for invalid input detection

## Testing Implications

### Critical Test Cases
1. **Empty input** (`slen == 0`)
2. **Single character inputs** for each character type
3. **Quote context at position 0** with different flag combinations
4. **End of input scenarios** (position equals length)
5. **Maximum length inputs** to test position arithmetic
6. **Invalid UTF-8 sequences** for character parser robustness

### Edge Cases Requiring Verification
- Position at string boundary (`pos == slen`)
- Malformed quote sequences
- Very long tokens approaching 32-byte limit
- Character sequences that don't produce tokens (whitespace, comments)

## Conclusion

The `libinjection_sqli_tokenize` function implements a robust, efficient streaming tokenizer with clear behavioral contracts. While the core algorithm is sound, the Rust port should address the unverified safety assumptions and improve error handling while preserving the performance characteristics that make it suitable as a foundational component.