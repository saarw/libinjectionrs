# Phase 1.2: Data Flow Analysis - libinjection_xss

## Input Analysis and Constraints

### Function Signatures
```c
int libinjection_xss(const char *s, size_t slen)
int libinjection_is_xss(const char *s, size_t len, int flags)
```

### Input Parameters
- **`s`**: Raw input string, may contain null bytes, not required to be null-terminated
- **`len`/`slen`**: Length of input string in bytes
- **`flags`**: HTML parsing context (only in `libinjection_is_xss`)

### Input Constraints
- Input string can be NULL (handled gracefully by HTML5 parser)
- Length can be 0 (empty input is safe)
- Input may contain arbitrary bytes including null bytes
- No maximum length constraint (limited only by available memory)
- Input encoding is treated as raw bytes (no UTF-8 validation)

## Buffer Manipulation Sequences

### HTML5 Parser State Buffer Management
```
h5_state_t h5 initialization:
    h5.s = s              // Original input pointer (read-only)
    h5.len = len          // Total input length
    h5.pos = 0            // Current parsing position
    h5.token_start = NULL // Start of current token
    h5.token_len = 0      // Length of current token
```

### Token Extraction Flow
```
libinjection_h5_next(&h5) processes:
    1. Advance h5.pos through input buffer
    2. Set h5.token_start to point into original buffer s
    3. Set h5.token_len to token byte length
    4. Set h5.token_type to classify token
    
No buffer copying or modification occurs - all operations work on pointers into original input.
```

### String Comparison Operations
The system uses specialized comparison functions that work directly on the input buffer:

```c
cstrcasecmp_with_null(const char *a, const char *b, size_t n)
```
- Compares uppercase template `a` against raw input `b[0..n]`
- Skips embedded null bytes in input `b`
- Performs case-insensitive matching by uppercasing input characters
- Returns 0 for match, 1 for mismatch

```c
htmlencode_startswith(const char *a, const char *b, size_t n)  
```
- HTML decodes input `b` on-the-fly during comparison
- Compares against uppercase template `a`
- Skips leading whitespace and control characters
- Ignores null bytes and vertical tabs in input

## State Variable Modifications

### Primary State Variables
```c
h5_state_t h5;           // HTML5 parser state (modified by libinjection_h5_next)
attribute_t attr;        // Current attribute classification (local state)
```

### Attribute State Transitions
```
attr state lifecycle:
    INITIAL: attr = TYPE_NONE
    
    ATTR_NAME token → attr = is_black_attr(token)
        ├─► TYPE_NONE (safe attribute)
        ├─► TYPE_BLACK (dangerous attribute) 
        ├─► TYPE_ATTR_URL (URL attribute)
        ├─► TYPE_STYLE (style attribute)
        └─► TYPE_ATTR_INDIRECT (indirect attribute)
    
    ATTR_VALUE token → use attr for validation, then attr = TYPE_NONE
    
    Any other token → attr = TYPE_NONE (reset context)
```

### HTML5 Parser Internal State (opaque)
- **Position tracking**: `h5.pos` advances through input
- **Token boundaries**: `h5.token_start` and `h5.token_len` set by parser
- **Parse state**: Internal state machine position (context-dependent)
- **Close tag detection**: `h5.is_close` flag for closing tags

## Output Generation Logic

### Binary Return Values
```c
Return 1: XSS detected (dangerous input)
Return 0: No XSS detected (safe input)
```

### XSS Detection Triggers (Return 1 Paths)
1. **DOCTYPE detection**: Any DOCTYPE token triggers immediate return 1
2. **Blacklisted tags**: TAG_NAME_OPEN matching blacklisted tag names
3. **Event handlers**: ATTR_VALUE following TYPE_BLACK attribute
4. **Dangerous URLs**: ATTR_VALUE with dangerous protocol in URL attribute
5. **Style injection**: ATTR_VALUE following TYPE_STYLE attribute  
6. **Indirect attributes**: ATTR_VALUE containing blacklisted attribute name
7. **Comment exploits**: TAG_COMMENT with dangerous patterns

### Multi-Context Wrapper Logic
```
libinjection_xss() return value:
    = libinjection_is_xss(s, len, DATA_STATE)
   || libinjection_is_xss(s, len, VALUE_NO_QUOTE)
   || libinjection_is_xss(s, len, VALUE_SINGLE_QUOTE) 
   || libinjection_is_xss(s, len, VALUE_DOUBLE_QUOTE)
   || libinjection_is_xss(s, len, VALUE_BACK_QUOTE)
```

Short-circuit evaluation: Returns 1 as soon as any context detects XSS.

## Error Propagation Paths

### HTML Entity Decoding Errors
```c
html_decode_char_at(src, len, consumed) error handling:
    - NULL input → *consumed = 0, return -1
    - Invalid hex digits → return partial result, continue parsing
    - Value overflow (> 0x1000FF) → return '&' (treat as literal)
    - Unterminated entity → return partial result
```

### Comparison Function Error Handling
```c
cstrcasecmp_with_null() edge cases:
    - Null template string → undefined behavior (not handled)
    - Zero length input → matches empty template only
    - Input shorter than template → mismatch
```

### HTML5 Parser Error Propagation  
The HTML5 parser is designed to be fault-tolerant:
- Invalid HTML syntax does not cause errors, but continues parsing
- Malformed tokens are classified as best-effort
- End-of-input conditions are handled gracefully
- No memory allocation failures (works on pre-existing buffers)

### No Exception Handling
The C implementation uses only return values for error signaling:
- Functions return success/failure status
- Invalid input is handled gracefully rather than failing
- No dynamic memory allocation means no out-of-memory errors

## Memory Access Patterns

### Read-Only Input Access
```
Input buffer s[0..len-1]:
    - Read access only throughout processing
    - Bounds checking via len parameter  
    - Multiple overlapping reads during token extraction
    - No modification of original input data
```

### Stack-Only Data Structures
```
Local variables on call stack:
    - h5_state_t h5 (~64 bytes structure)
    - attribute_t attr (integer enum)
    - Loop variables and temporary values
    
No heap allocation, no memory ownership issues.
```

### Pointer Arithmetic Safety
```
Token pointer management:
    h5.token_start points into s[0..len-1]
    h5.token_len ≤ (s + len - h5.token_start)
    
Bounds checking enforced by HTML5 parser state machine.
```