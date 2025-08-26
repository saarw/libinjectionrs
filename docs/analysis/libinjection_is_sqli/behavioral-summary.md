# Behavioral Summary: libinjection_is_sqli

**Function**: `libinjection_is_sqli`  
**File**: `libinjection-c/src/libinjection_sqli.c`  
**Lines**: `2244-2316`  
**Analysis Date**: `2025-08-26`

---

## Complete Behavioral Description

The `libinjection_is_sqli` function serves as the primary SQL injection detection engine in libinjection. It implements a multi-context fingerprinting approach that tests input strings in different SQL parsing scenarios to detect injection patterns. The function operates by sequentially testing the input in three contexts: as-is (unquoted), single-quoted, and double-quoted strings, using both ANSI SQL and MySQL parsing rules when appropriate. For each context, it generates a fingerprint of the parsed SQL tokens and looks up this fingerprint in a blacklist of known injection patterns. The function returns `TRUE` immediately upon finding any match, implementing short-circuit evaluation for performance. If no matches are found in any context, it returns `FALSE`, indicating the input is likely benign.

## Key Properties

1. **Multi-Context Detection**: Tests input in up to 6 different parsing contexts (3 quote contexts × 2 SQL dialects)
2. **Short-Circuit Evaluation**: Returns `TRUE` immediately upon first positive match, optimizing performance
3. **Context-Aware Parsing**: Only tests quote contexts when relevant quote characters are present in input
4. **Dialect-Sensitive**: Automatically switches to MySQL parsing when comment patterns suggest MySQL-specific syntax
5. **Stateless Operation**: Function behavior depends only on input parameters, making it thread-safe

## Complexity Analysis

- **Time Complexity**: O(n·k) where n is input length and k is number of contexts tested (maximum 6)
  - Each context requires tokenization and fingerprinting: O(n)
  - Quote character detection: O(n) via `memchr`
  - Maximum 6 context tests in worst case
- **Space Complexity**: O(1) - Uses fixed-size buffers and no dynamic allocation
- **Call Complexity**: Makes 1-6 calls to `libinjection_sqli_fingerprint` plus equal number of lookup calls

## Dependencies

### Direct Dependencies
- `libinjection_sqli_fingerprint()`: Core tokenization and fingerprint generation
- `sql_state->lookup()`: Callback function for fingerprint blacklist lookup  
- `reparse_as_mysql()`: Heuristic to determine MySQL parsing necessity
- `memchr()`: Standard C library function for character searching
- `strlen()`: Standard C library function for string length calculation

### Data Dependencies
- `libinjection_sqli_state` structure: Input data, configuration, and working buffers
- Flag constants: `FLAG_QUOTE_NONE`, `FLAG_QUOTE_SINGLE`, `FLAG_QUOTE_DOUBLE`, `FLAG_SQL_ANSI`, `FLAG_SQL_MYSQL`
- Character constants: `CHAR_SINGLE` (`'`), `CHAR_DOUBLE` (`"`)
- Lookup type constant: `LOOKUP_FINGERPRINT`

### Indirect Dependencies
- SQL tokenization logic (via fingerprinting function)
- Blacklist pattern database (via lookup callback)
- Comment detection statistics (for MySQL reparsing decision)

## Critical Behaviors for Rust Implementation

### Must Preserve Exactly

1. **Context Testing Order**: Test as-is → single-quote → double-quote contexts in exactly this sequence
2. **MySQL Reparsing Logic**: Only attempt MySQL parsing when `stats_comment_ddx > 0 || stats_comment_hash > 0`
3. **Quote Presence Checks**: Only test quote contexts when `memchr` finds the relevant quote character
4. **Short-Circuit Returns**: Return `TRUE` immediately upon first positive fingerprint match
5. **Empty Input Handling**: Return `FALSE` immediately when `slen == 0`
6. **Flag Combinations**: Use exact flag combinations for each context:
   - As-is ANSI: `FLAG_QUOTE_NONE | FLAG_SQL_ANSI`
   - As-is MySQL: `FLAG_QUOTE_NONE | FLAG_SQL_MYSQL`
   - Single-quote ANSI: `FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI`
   - Single-quote MySQL: `FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL`
   - Double-quote MySQL: `FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL`

### Implementation Challenges for Rust

- **Function Pointer Callbacks**: Replace C function pointers with Rust trait objects or closures
- **Mutable State Management**: Handle mutable state updates during fingerprinting while maintaining borrowing rules
- **Buffer Management**: Replace fixed C arrays with appropriate Rust collections (Vec, SmallVec, or arrays)
- **Error Handling**: Add proper error handling for cases that cause undefined behavior in C (NULL pointers, invalid state)
- **Memory Safety**: Ensure all buffer accesses are bounds-checked and eliminate potential undefined behavior

### Verification Strategy

1. **Differential Testing**: Compare outputs with original C implementation across comprehensive test suite
2. **Property Testing**: Verify invariants hold for random inputs (empty → FALSE, positive match → TRUE)
3. **Edge Case Testing**: Test boundary conditions (empty input, single characters, quote-only inputs)
4. **Context Testing**: Verify each parsing context produces expected results independently
5. **Performance Testing**: Ensure short-circuit evaluation provides expected performance characteristics