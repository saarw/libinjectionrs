# Function Analysis: libinjection_is_sqli

**File**: `libinjection-c/src/libinjection_sqli.c`  
**Lines**: `2244-2316`  

---

## Phase 1.3: Invariant Discovery

### Mathematical Relationships

- **Invariant 1**: `slen >= 0` - String length is non-negative (size_t is unsigned)
- **Invariant 2**: `if slen == 0 then return == FALSE` - Empty input always results in no detection
- **Invariant 3**: `return ∈ {TRUE, FALSE}` - Function always returns exactly one of two boolean values
- **Invariant 4**: `∀ fingerprint_test: if lookup(fingerprint) == TRUE then return == TRUE` - Any positive fingerprint match immediately returns true
- **Invariant 5**: `if memchr(s, '\'', slen) == NULL then single_quote_tests_skipped` - Single quote tests only run when single quotes are present
- **Invariant 6**: `if memchr(s, '"', slen) == NULL then double_quote_tests_skipped` - Double quote tests only run when double quotes are present
- **Invariant 7**: `reparse_as_mysql() == (stats_comment_ddx > 0 || stats_comment_hash > 0)` - MySQL reparsing depends on specific comment types

### Preconditions

**Required State at Function Entry:**
- `sql_state != NULL` - Function parameter must be valid pointer
- `sql_state->s` points to valid memory region of size `sql_state->slen` bytes (or is NULL if slen == 0)
- `sql_state->slen` accurately represents the number of accessible bytes at `sql_state->s`
- `sql_state->lookup` is a valid function pointer that accepts the specified parameters
- `sql_state->fingerprint` points to writable buffer of at least 8 bytes
- `sql_state` has been properly initialized (typically via `libinjection_sqli_init`)

**Parameter Constraints:**
- No explicit constraints on values within `sql_state->s` (can contain any byte values)
- `sql_state->slen` can be 0 (handled specially)
- `sql_state` structure must be properly aligned and accessible

**Global Assumptions:**
- `CHAR_SINGLE` constant equals `'\''` (ASCII 39)
- `CHAR_DOUBLE` constant equals `'"'` (ASCII 34)
- `TRUE` and `FALSE` constants are defined (typically 1 and 0)
- `memchr`, `strlen` functions behave according to C standard

### Postconditions

**Guaranteed State at Function Exit:**
- Return value is exactly `TRUE` or `FALSE`
- `sql_state->fingerprint` contains a valid C string (null-terminated) if any fingerprinting occurred
- `sql_state->stats_*` fields may have been incremented during fingerprinting process
- Original input data at `sql_state->s` is unmodified (const correctness)

**Return Value Meaning:**
- `TRUE` (1): Input contains SQL injection patterns detectable by fingerprinting in at least one context
- `FALSE` (0): Input is either empty OR no SQL injection patterns detected in any tested context

**Global State Changes:**
- No global variables modified
- No file system or network I/O
- Only `sql_state` structure is modified (and only specific fields)

### Loop Invariants

**No Loops in this Function:**
This function contains no loops - it is a sequential series of conditional branches with early returns.

### Memory Safety Properties

**Valid Pointers:**
- `sql_state` must remain valid throughout function execution
- `sql_state->s` must be valid for `slen` bytes if `slen > 0`
- `sql_state->lookup` function pointer must remain valid
- `sql_state->fingerprint` must point to valid 8-byte buffer

**Buffer Bounds:**
- All buffer access is bounds-checked via `slen` parameter
- `memchr(s, char, slen)` calls are properly bounded
- No direct array indexing performed in this function
- Fingerprint buffer size (8 bytes) is sufficient for libinjection fingerprints (max 5-6 characters + null terminator)

**Lifetime Guarantees:**
- Function does not allocate or deallocate memory
- All pointers used have lifetime >= function execution time
- No dangling pointer issues possible within function scope

**Potential Safety Issues:**
- Undefined behavior if `sql_state` is NULL
- Undefined behavior if `sql_state->s` is invalid but `slen > 0`
- Potential crash if `sql_state->lookup` function pointer is invalid
- Buffer overflow possible in called functions if `sql_state->fingerprint` buffer is too small

### Implicit Contracts

**Caller Assumptions:**
- Caller has properly initialized `sql_state` structure via `libinjection_sqli_init` or equivalent
- Caller ensures `sql_state->s` points to valid memory for `slen` bytes
- Caller provides valid lookup function that can handle `LOOKUP_FINGERPRINT` requests
- Caller ensures thread safety if multiple threads access same `sql_state`

**Caller Guarantees:**
- Function will not modify original input data (`sql_state->s`)
- Function will return exactly `TRUE` or `FALSE`
- Function will not perform any I/O operations
- Function execution time is bounded (no infinite loops)
- Function will not leak memory or other resources

**Inter-function Dependencies:**
- `libinjection_sqli_fingerprint()`: Must generate valid fingerprints and update statistics
- `sql_state->lookup()`: Must perform fingerprint lookup and return boolean result
- `reparse_as_mysql()`: Must return boolean based on comment statistics
- `memchr()`: Standard C library function for memory search
- `strlen()`: Standard C library function for string length

### Edge Cases Identified

**Boundary Conditions:**
- ✓ Empty input (`slen == 0`) - Returns FALSE immediately
- ✓ NULL input string with zero length - Handled correctly
- ✓ Single character input - Will be processed through normal path
- ✓ Maximum size input - Limited by `size_t` range, no special handling needed
- ✓ Input containing only quotes - Will be tested in quote contexts

**Character Boundary Cases:**
- Input with single quotes but no actual SQL injection
- Input with double quotes but no actual SQL injection  
- Input with both single and double quotes
- Input with MySQL-specific comment syntax (`--x` vs `-- `)
- Input with hash comments (`# comment`)

**Function Interaction Cases:**
- Fingerprinting function fails or returns empty fingerprint
- Lookup function returns unexpected values (should be boolean)
- Statistics counters overflow (int overflow)
- Very long fingerprints (should not exceed 8-byte buffer)

**Resource Conditions:**
- Stack overflow with deeply nested function calls (unlikely in this simple function)
- Invalid function pointer in `sql_state->lookup`
- Corrupted `sql_state` structure

### Critical Implementation Properties

**Monotonicity:** Once a positive match is found, function returns immediately (short-circuit evaluation)

**Determinism:** Given identical input, function always produces identical output (assuming deterministic lookup function)

**Context Independence:** Each context test (as-is, single-quote, double-quote) is independent

**Ordering Dependency:** Context tests must be performed in specific order due to MySQL reparsing logic