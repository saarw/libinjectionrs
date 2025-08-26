# Phase 1.3: Invariant Discovery - libinjection_sqli_tokenize

## Mathematical Relationships

### Position Bounds
- **Invariant**: `0 ≤ sf->pos ≤ sf->slen` (always)
- **Location**: Maintained by loop condition `pos < slen` and parser implementations
- **Violation**: Would cause buffer overrun or infinite loop
- **Checking**: Loop bounds check prevents violation

### Token Count Relationship  
- **Invariant**: `sf->stats_tokens` increases by 0 or 1 per call
- **Expression**: `stats_tokens_new = stats_tokens_old + (token_found ? 1 : 0)`
- **Location**: Established at `sf->stats_tokens += 1` statements
- **Violation**: Multiple increments would indicate logic error

### String Length Relationship
- **Invariant**: `sf->slen` remains constant throughout execution
- **Expression**: `slen_final = slen_initial` 
- **Location**: Local copy prevents modification
- **Violation**: Would indicate memory corruption

### Character Bounds
- **Invariant**: Character read is valid when `pos < slen`
- **Expression**: `s[pos]` is valid ⟺ `pos < slen`
- **Location**: Loop condition protects character access
- **Violation**: Buffer overrun if condition bypassed

## Preconditions

### Required Preconditions
1. **Non-null State Pointer**
   - **Condition**: `sf != NULL`
   - **Assumption**: Implicit - no explicit check
   - **Violation Effect**: Segmentation fault

2. **Valid String Pointer (when slen > 0)**
   - **Condition**: `sf->s != NULL` when `sf->slen > 0`
   - **Assumption**: Implicit - no explicit check
   - **Violation Effect**: Segmentation fault on character access

3. **Valid Current Token Pointer** 
   - **Condition**: `sf->current != NULL`
   - **Assumption**: Should point to valid stoken_t structure
   - **Violation Effect**: Segmentation fault in st_clear()

4. **Consistent Length**
   - **Condition**: `sf->slen` accurately reflects string length
   - **Assumption**: Caller responsibility
   - **Violation Effect**: Buffer overrun or premature termination

5. **Valid Position**
   - **Condition**: `sf->pos ≤ sf->slen`
   - **Assumption**: State properly maintained between calls
   - **Violation Effect**: Buffer overrun

### Optional Preconditions
1. **Initialized Flags**
   - **Condition**: `sf->flags` contains valid flag values
   - **Default**: Function handles any flag values gracefully
   - **Effect**: Only affects quote context handling

## Postconditions

### Guaranteed Postconditions

1. **Position Advancement**
   - **Condition**: `sf->pos_final ≥ sf->pos_initial`
   - **Location**: All parser functions either advance or maintain position
   - **Exception**: None - position never decreases

2. **Bounded Position**
   - **Condition**: `sf->pos ≤ sf->slen`
   - **Location**: Loop termination ensures this
   - **Exception**: None

3. **Token State Consistency**
   - **Condition**: `return TRUE ⟺ sf->current->type != CHAR_NULL`
   - **Location**: Return logic at end of function
   - **Exception**: None - strict correlation

4. **Statistics Consistency**
   - **Condition**: `return TRUE ⟹ sf->stats_tokens_final = sf->stats_tokens_initial + 1`
   - **Location**: Token found paths increment counter
   - **Exception**: None

### Return-Path-Specific Postconditions

**Return TRUE Path**:
- `sf->current` contains valid token data
- `sf->pos` advanced past token
- `sf->stats_tokens` incremented by 1

**Return FALSE Path**:
- `sf->current` may be cleared
- `sf->pos` may be advanced to end or unchanged
- `sf->stats_tokens` unchanged

## Loop Invariants

### Main Parsing Loop
```c
while (*pos < slen) { ... }
```

**Invariants**:
1. **Position Bounds**: `0 ≤ *pos ≤ slen` (maintained at loop entry/exit)
2. **String Validity**: `s[*pos]` is valid character when `*pos < slen`
3. **State Consistency**: `sf->current` points to valid token structure
4. **Progress**: Each iteration either produces token (exit) or advances position

**Loop Termination**:
- **Guarantee**: `*pos` eventually reaches `slen` or token is found
- **Proof**: Parsers must advance position or produce token
- **Failure Mode**: Infinite loop if parser returns same position without token

## Memory Safety Properties

### Pointer Validity
1. **`sf` pointer**: Assumed valid throughout - **unchecked assumption**
2. **`sf->s` pointer**: Used without NULL check when `slen > 0` - **potential vulnerability**
3. **`sf->current` pointer**: Used without NULL check - **potential vulnerability**

### Buffer Bounds
1. **Input buffer `sf->s`**: Protected by `pos < slen` check ✓
2. **Token buffer `sf->current->val`**: **Not bounds-checked by this function**
   - Parser functions may overflow val[32] array
   - Responsibility delegated to parser implementations

### Use-After-Free Analysis
- **No dynamic allocation**: Function doesn't allocate memory
- **No deallocation**: Function doesn't free memory  
- **No dangling pointers**: Only uses provided structure fields

### Double-Free Analysis
- **Not applicable**: No memory management in this function

## Implicit Contracts

### Caller Contracts
1. **Initialization**: Caller must initialize `sf` structure properly
2. **Memory Management**: Caller owns `sf` structure lifetime
3. **String Lifetime**: Input string must remain valid during call
4. **Parser Table**: Global `char_parse_map` must be properly initialized

### Callee Contracts  
1. **Position Update**: Function guarantees position advancement or termination
2. **Token Production**: Function produces at most one token per call
3. **State Preservation**: Failed parsing doesn't corrupt structure
4. **Statistics**: Accurate token counting maintained

### Parser Function Contracts
1. **Position Advancement**: Must advance position OR produce token
2. **Bounds Respect**: Must not read beyond `sf->slen`
3. **Token Population**: If token produced, must set `type != CHAR_NULL`
4. **Return Value**: Must return new position value

## Edge Case Systematic Analysis

### Empty Inputs
- **`slen == 0`**: Returns FALSE immediately ✓
- **`sf->s == NULL && slen == 0`**: Safe - no string access ✓
- **`sf->s == NULL && slen > 0`**: **Undefined behavior - segfault**

### Boundary Values
- **`pos == 0`**: Special quote context handling ✓
- **`pos == slen-1`**: Last character, normal processing ✓  
- **`pos == slen`**: Loop termination, returns FALSE ✓

### Maximum Size Inputs
- **`slen == SIZE_MAX`**: Potential integer overflow in position arithmetic
- **Very long strings**: Limited by system memory and position arithmetic

### Invalid Data
- **Malformed UTF-8**: Handled at character level by parsers
- **Binary data**: Each byte processed as character
- **Null bytes**: Treated as regular characters (not string terminators)

### Resource Exhaustion
- **Stack overflow**: Deep parser recursion could exhaust stack
- **Memory exhaustion**: No dynamic allocation, not applicable

## Critical Invariant Summary

### Function-Level Invariants
1. `0 ≤ sf->pos ≤ sf->slen` (always)
2. `return TRUE ⟺ sf->current->type != CHAR_NULL`
3. Single token per successful call
4. Position monotonically non-decreasing

### Global System Invariants  
1. `char_parse_map[256]` contains valid function pointers
2. Parser functions respect position/bounds contracts
3. Token structures properly sized and aligned

### Assumptions Requiring Verification
1. **Unchecked**: `sf != NULL`
2. **Unchecked**: `sf->s != NULL` when `slen > 0`  
3. **Unchecked**: `sf->current != NULL`
4. **Trusted**: Parser functions implement contracts correctly
5. **Trusted**: Global parsing tables properly initialized