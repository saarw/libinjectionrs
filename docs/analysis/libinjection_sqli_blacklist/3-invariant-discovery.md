# Phase 1.3: Invariant Discovery - libinjection_sqli_blacklist

## Mathematical Relationships

### Input-Output Relationship
```
f(fingerprint) = {
  FALSE  if len(fingerprint) < 1
  FALSE  if is_keyword(v1_format(fingerprint)) ≠ TYPE_FINGERPRINT  
  TRUE   if is_keyword(v1_format(fingerprint)) = TYPE_FINGERPRINT
}
```

Where:
- `v1_format(fp) = "0" + uppercase(fp)`
- `len(fp) = strlen(fp)`
- `TYPE_FINGERPRINT = 'F' = 70`

### Format Conversion Function
```
v1_format: String → String
v1_format(s) = "0" + Σ(i=0 to len(s)-1) uppercase(s[i])

where uppercase(c) = {
  c - 32  if 'a' ≤ c ≤ 'z'
  c       otherwise
}
```

### Length Relationships
- Input fingerprint length: `0 ≤ len(input) ≤ 5` (typical constraint)
- Output v1 fingerprint length: `len(output) = len(input) + 1`
- Buffer requirement: `len(output) + 1 ≤ 8` (including null terminator)

## Preconditions

### Function Entry Preconditions
1. **Valid Pointer**: `sql_state ≠ NULL`
2. **Valid Fingerprint**: `sql_state->fingerprint` is a valid C-string
3. **Null Termination**: `sql_state->fingerprint` is null-terminated
4. **Reasonable Length**: `strlen(sql_state->fingerprint) ≤ 6` (practical limit)

### System State Preconditions
1. **Database Initialized**: `sql_keywords` database is properly loaded
2. **Function Available**: `is_keyword()` function is accessible
3. **Memory Valid**: Stack has sufficient space for local variables

## Postconditions

### Successful Execution (Return TRUE)
1. **Pattern Match**: `is_keyword(v1_format(fingerprint)) = TYPE_FINGERPRINT`
2. **State Preserved**: Original `sql_state->fingerprint` unchanged
3. **No Side Effects**: No global state modifications
4. **Deterministic**: Same input always produces TRUE

### Failed Execution (Return FALSE)
1. **Reason Set**: `sql_state->reason` contains specific line number
2. **State Preserved**: Original `sql_state->fingerprint` unchanged  
3. **Two Failure Modes**:
   - Empty fingerprint: `reason = 1987`
   - No pattern match: `reason = 2017`

### Universal Postconditions
1. **Memory Safety**: No buffer overflows occurred
2. **Thread Safety**: No race conditions introduced
3. **Exception Safety**: No undefined behavior

## Loop Invariants

### Format Conversion Loop
```c
for (i = 0; i < len; ++i) {
    // Loop invariant at start of iteration i:
    // ∀j ∈ [0, i): fp2[j+1] = uppercase(sql_state->fingerprint[j])
    // fp2[0] = '0'
    // i ≤ len ≤ strlen(sql_state->fingerprint)
}
```

**Invariant Properties**:
- **Initialization**: `fp2[0] = '0'` before loop entry
- **Maintenance**: Each iteration correctly converts `fingerprint[i]` to `fp2[i+1]`
- **Termination**: Loop terminates when `i = len`
- **Bounds Safety**: `i+1 < 8` maintained by length constraints

### Post-loop State
```
// After loop completion:
// fp2[0] = '0'
// ∀j ∈ [0, len): fp2[j+1] = uppercase(sql_state->fingerprint[j])  
// fp2[len+1] = '\0'
```

## Memory Safety Properties

### Buffer Bounds Invariants
1. **Local Buffer**: `fp2` has exactly 8 bytes allocated
2. **Write Bounds**: All writes to `fp2` satisfy `index < 8`
3. **Read Bounds**: All reads from `fingerprint` satisfy `index < strlen(fingerprint)`

### Memory Access Properties
```
// Write access pattern:
// fp2[0] ← '0'                    (safe: 0 < 8)
// fp2[i+1] ← converted_char       (safe: i+1 ≤ len ≤ 6 < 8)
// fp2[len+1] ← '\0'              (safe: len+1 ≤ 6 < 8)

// Read access pattern:
// sql_state->fingerprint[i]       (safe: i < len = strlen(fingerprint))
```

### Stack Safety
- **Minimum Size**: 8 bytes ensures GCC `-fstack-protector` compatibility
- **Alignment**: Natural alignment for `char` array
- **Lifetime**: Buffer valid for entire function execution

## Implicit Contracts

### Fingerprint Format Contract
1. **Character Set**: Fingerprint contains valid SQL token type characters
2. **Length Bounds**: Reasonable length for pattern matching (≤ 5-6 characters)
3. **Semantic Validity**: Represents actual SQL token sequence

### Database Contract
1. **Completeness**: Database contains all known SQLi fingerprint patterns
2. **Consistency**: TYPE_FINGERPRINT markers correctly identify malicious patterns
3. **Performance**: Binary search provides O(log n) lookup time

### Caller Contract
1. **Input Validation**: Caller ensures `sql_state` is valid
2. **Error Handling**: Caller checks return value and handles FALSE appropriately
3. **State Management**: Caller manages `sql_state` lifecycle

## Correctness Properties

### Functional Correctness
```
∀ valid_fingerprint fp:
  libinjection_sqli_blacklist(state_with(fp)) = TRUE
  ⟺ is_known_sqli_pattern(fp)
```

### Error Handling Correctness
```
∀ invalid_input inp:
  libinjection_sqli_blacklist(inp) = FALSE ∧
  inp.reason ∈ {1987, 2017}
```

### Idempotency
```
∀ sql_state s:
  libinjection_sqli_blacklist(s) = libinjection_sqli_blacklist(s)
  (assuming deterministic database lookup)
```

### Monotonicity
The function is monotonic with respect to fingerprint validity:
- Valid, matching fingerprints → TRUE
- Invalid or non-matching fingerprints → FALSE
- No partial or ambiguous results

## Performance Invariants

### Time Complexity Bounds
- **Best Case**: O(log n) where n = database size
- **Worst Case**: O(log n) + O(m) where m = fingerprint length
- **Conversion Overhead**: O(m) for format transformation

### Space Complexity Bounds
- **Stack Space**: O(1) - fixed 8-byte buffer
- **Heap Space**: O(0) - no dynamic allocation
- **Database Space**: O(1) from function perspective (external dependency)

### Cache Efficiency Properties
1. **Sequential Access**: Format conversion has good cache locality
2. **Binary Search**: Database lookup has logarithmic cache efficiency
3. **Small Working Set**: Minimal memory footprint