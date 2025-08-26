# Phase 1.2: Data Flow Analysis - libinjection_sqli_fold

**Function Location**: `libinjection-c/src/libinjection_sqli.c`  
**Function Signature**: `int libinjection_sqli_fold(struct libinjection_sqli_state *sf)`

## 1. Input Analysis

### Function Parameters
| Parameter | Type | Purpose | Constraints |
|-----------|------|---------|-------------|
| `sf` | `struct libinjection_sqli_state *` | SQL parsing state container | Must not be NULL |

### Parameter Analysis: `sf` Structure Members Used

**Direct Reads:**
- `sf->tokenvec[]` - Token array (read for pattern matching)
- `sf->tokenvec[pos].type` - Token type classification  
- `sf->tokenvec[pos].val` - Token string value
- `sf->tokenvec[pos].len` - Token string length
- `sf->flags` - Parser configuration flags (FLAG_SQL_MYSQL, etc.)

**Direct Writes:**  
- `sf->current` - Pointer to current token being processed
- `sf->tokenvec[].type` - Modified during type conversions
- `sf->stats_folds` - Incremented on each folding operation

**Expected Input Constraints:**
- `sf != NULL` (undefined behavior if violated)
- `sf->tokenvec` must be properly initialized by prior tokenization
- `sf->current` should point to valid tokenvec entry
- Initial token stream should contain meaningful tokens from tokenization

**Invalid Input Handling:**
- **NULL `sf`**: Function will crash (no explicit null check)
- **Uninitialized tokens**: May lead to undefined pattern matching behavior
- **Corrupted token types**: May cause incorrect folding or infinite loops

### Implicit Inputs
- **Global Constants**: `LIBINJECTION_SQLI_MAX_TOKENS` (value: 5)
- **Token Type Constants**: TYPE_* enumeration values
- **Static Functions**: `libinjection_sqli_tokenize()`, `st_is_unary_op()`, `syntax_merge_words()`, etc.
- **String Comparison Function**: `cstrcasecmp()`

## 2. Buffer Manipulation Sequences

### Primary Data Structure: `sf->tokenvec[]`

**Buffer Layout:**
```
sf->tokenvec[0] sf->tokenvec[1] sf->tokenvec[2] sf->tokenvec[3] sf->tokenvec[4] sf->tokenvec[5]
     ↑               ↑               ↑               ↑               ↑               ↑
   pos=0           pos=1           pos=2           pos=3           pos=4      (overflow)
```

**Buffer Access Patterns:**

1. **Sequential Read Pattern** (Pattern Matching):
   ```c
   // Read consecutive tokens for pattern analysis
   sf->tokenvec[left].type        // First token type
   sf->tokenvec[left + 1].type    // Second token type  
   sf->tokenvec[left + 2].type    // Third token type (when available)
   ```

2. **Token Copy/Move Pattern** (Folding Operations):
   ```c
   // Copy token from right to left (removing middle tokens)
   st_copy(&sf->tokenvec[left], &sf->tokenvec[left + 1]);
   st_copy(&sf->tokenvec[left + 1], &sf->tokenvec[left + 2]);
   
   // Special case: copy from overflow position
   st_copy(&(sf->tokenvec[1]), &(sf->tokenvec[LIBINJECTION_SQLI_MAX_TOKENS]));
   ```

3. **Pointer Assignment Pattern**:
   ```c
   sf->current = &(sf->tokenvec[pos]);  // Point to token at position pos
   ```

**Buffer Bounds Analysis:**
- **Normal Access**: `sf->tokenvec[0]` to `sf->tokenvec[4]` (indices 0-4)
- **Overflow Access**: `sf->tokenvec[5]` (index 5) - Used temporarily during special 5-token handling
- **Bounds Checking**: Limited - relies on `LIBINJECTION_SQLI_MAX_TOKENS` constraint
- **Potential Overrun**: If `pos` exceeds 5 due to logic error, buffer overrun possible

### Position Variables Manipulation

**Variable: `pos` (size_t)**
- **Initial**: 0
- **Increment Operations**: `pos += 1` (after successful tokenization)
- **Decrement Operations**: `pos -= 1` or `pos -= 2` (during folding)
- **Reset Operations**: `pos = 1` or `pos = 2` (special 5-token handling)
- **Bounds**: `0 <= pos <= LIBINJECTION_SQLI_MAX_TOKENS + 1`

**Variable: `left` (size_t)**  
- **Initial**: 0
- **Assignment Operations**: `left = 0` (restart folding analysis)
- **Increment Operations**: `left += 1` (advance processing position)
- **Assignment from pos**: `left = pos` (when insufficient tokens)
- **Bounds**: `0 <= left <= pos`

**Position Relationship Invariant**: `left <= pos` (always maintained)

## 3. State Variable Modifications

### Local Variables

| Variable | Type | Lifecycle | Purpose |
|----------|------|-----------|---------|
| `last_comment` | `stoken_t` | Function scope | Preserve last comment token |
| `pos` | `size_t` | Function scope | Next token insertion position |
| `left` | `size_t` | Function scope | Count of finalized tokens |
| `more` | `int` | Function scope | Tokenization continuation flag |

### State Evolution Through Function

**Phase 1: Initialization**
```
pos = 0, left = 0, more = 1
last_comment.type = CHAR_NULL
sf->current = &(sf->tokenvec[0])
```

**Phase 2: Initial Skip**
```
more = libinjection_sqli_tokenize(sf)  // Modifies sf->current
// pos remains 0 during skipping
// left remains 0
```

**Phase 3: First Real Token**  
```
pos = 1  // First non-skipped token accepted
left = 0 // Still no finalized tokens
```

**Phase 4: Main Folding Loop**
```
// Tokenization phase
pos += 1  // For each new token
sf->current = &(sf->tokenvec[pos])  // Update current pointer

// Folding phase  
pos -= 1 or pos -= 2  // When tokens are folded
sf->stats_folds += 1  // Increment fold counter

// Advancement phase
left += 1  // When no folding occurs, advance processing
```

**Phase 5: Final Cleanup**
```
left = final token count (≤ LIBINJECTION_SQLI_MAX_TOKENS)
```

### External State Modifications

**Structure Member: `sf->current`**
- Modified continuously to point to active token
- Used by `libinjection_sqli_tokenize()` for output

**Structure Member: `sf->stats_folds`**
- Incremented each time a folding operation occurs
- Accumulates total folding operations performed

**Structure Member: `sf->tokenvec[]`**
- Token types modified during type conversions
- Token positions shuffled during folding operations

## 4. Output Generation Logic

### Return Value Computation
```c
return (int)left;
```

**Return Value Meaning**: Number of tokens remaining after folding
**Return Value Range**: `0 <= return_value <= LIBINJECTION_SQLI_MAX_TOKENS`

### Return Value Determination Logic

**Case 1: Empty Input**
```c
if (!more) {
    return 0;  // No meaningful tokens found
}
```

**Case 2: Normal Processing**
```c
// Main loop terminates when:
if (!more || left >= LIBINJECTION_SQLI_MAX_TOKENS) {
    left = pos;
    break;
}
// Return final left value
return (int)left;
```

**Case 3: Overflow Handling**
```c
if (left > LIBINJECTION_SQLI_MAX_TOKENS) {
    left = LIBINJECTION_SQLI_MAX_TOKENS;
}
return (int)left;
```

### Output Parameter Modifications

**Modified: `sf->tokenvec[]`**
- Contains final folded token sequence
- Length indicated by return value
- Tokens beyond return value are undefined

**Modified: `sf->stats_folds`**
- Contains count of folding operations performed
- Used for debugging and performance metrics

**Modified: `sf->current`**
- Points to last processed token
- May be undefined after function returns

### Side Effects

**Performance Metrics Update**
- `sf->stats_folds` incremented for each folding operation
- Provides insight into input complexity and processing effort

**Token Stream Restructuring**
- Original token sequence is destructively modified
- Folded tokens overwrite original sequence
- No backup of original sequence maintained

## 5. Error Propagation Paths

### Error Detection Mechanisms

**Primary Error: Invalid Token Type**
```c
if (sf->tokenvec[left + 1].len == 0) {
    sf->tokenvec[left + 1].type = TYPE_EVIL;
    return (int)(left + 2);
}
```
- **Detection**: Zero-length token in specific context
- **Response**: Mark as TYPE_EVIL and return immediately  
- **Propagation**: Caller receives return value > expected

**Secondary Error: Buffer Bounds**
- **Detection**: Implicit through position constraints
- **Response**: Function logic prevents most overruns
- **Propagation**: Potential memory corruption if constraints violated

### Error Return Codes

**Normal Return**: `0 <= return_value <= 5`
- Indicates successful folding with return_value tokens remaining

**Error Return**: `return_value > 5`  
- Only occurs with TYPE_EVIL detection
- Indicates parsing should be aborted
- Return value `left + 2` provides position information

### Error Cleanup

**Minimal Cleanup**: Function performs minimal cleanup on error paths
- No dynamic memory to free
- Token array remains in partial state
- Caller responsible for interpreting error conditions

**State Consistency**: On error, `sf` structure may be in inconsistent state
- Some tokens may be folded, others not
- `sf->stats_folds` reflects operations performed up to error
- `sf->current` points to last processed token

### Resource Management

**No Resource Leaks**: Function allocates no dynamic resources
- All operations on stack variables or provided structure
- No file handles, memory allocations, or other resources to clean up

**Memory Safety**: Potential issues with buffer bounds  
- Relies on caller providing properly sized token array
- No explicit bounds checking on all array accesses
- Buffer overrun possible if logic constraints violated