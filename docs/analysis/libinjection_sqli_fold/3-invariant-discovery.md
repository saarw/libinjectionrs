# Phase 1.3: Invariant Discovery - libinjection_sqli_fold

**Function Location**: `libinjection-c/src/libinjection_sqli.c`  
**Function Signature**: `int libinjection_sqli_fold(struct libinjection_sqli_state *sf)`

## 1. Mathematical Relationships

### Core Position Relationships
1. **Position Ordering Invariant**: `0 ≤ left ≤ pos`
   - **Expression**: `left <= pos`
   - **Maintained**: Throughout entire function execution
   - **Established**: Initial assignment `left = 0, pos = 0`
   - **Violation**: Would indicate corrupted processing state

2. **Token Count Bound**: `pos ≤ LIBINJECTION_SQLI_MAX_TOKENS + 1`
   - **Expression**: `pos <= 6` (since MAX_TOKENS = 5)
   - **Maintained**: By tokenization loop bounds checking
   - **Established**: Loop conditions `pos <= LIBINJECTION_SQLI_MAX_TOKENS`
   - **Violation**: Buffer overrun would occur

3. **Processing Window**: `pos - left ≤ 3`
   - **Expression**: Token look-ahead never exceeds 3 positions
   - **Maintained**: By explicit loop conditions
   - **Established**: Loop bounds `(pos - left) < 2` and `pos - left < 3`
   - **Violation**: Would indicate logic error in tokenization control

4. **Return Value Bounds**: `0 ≤ return_value ≤ LIBINJECTION_SQLI_MAX_TOKENS`
   - **Expression**: `0 <= return_value <= 5` (normal operation)
   - **Exception**: `return_value > 5` only on TYPE_EVIL detection
   - **Maintained**: By final clamping `if (left > LIBINJECTION_SQLI_MAX_TOKENS) left = LIBINJECTION_SQLI_MAX_TOKENS`

### Folding Operation Mathematics  
5. **Token Reduction**: Folding operations always decrease token count
   - **Expression**: `pos_after = pos_before - 1` or `pos_after = pos_before - 2`
   - **Maintained**: All folding rules decrement pos
   - **Violation**: Would indicate accumulation instead of reduction

6. **Statistics Accumulation**: `stats_folds` monotonically increases
   - **Expression**: `sf->stats_folds_after ≥ sf->stats_folds_before`
   - **Maintained**: Only increment operations, no decrements
   - **Established**: `sf->stats_folds += 1` or `sf->stats_folds += 2`

### Buffer Bounds Relationships
7. **Array Access Safety**: All token array accesses within bounds
   - **Expression**: `0 ≤ index ≤ 5` for all `sf->tokenvec[index]` accesses
   - **Maintained**: By position constraints and bounds checking
   - **Critical Accesses**: `sf->tokenvec[left]`, `sf->tokenvec[left + 1]`, `sf->tokenvec[left + 2]`

## 2. Preconditions

### Function Entry Requirements
1. **Non-null Parameter**: `sf != NULL`
   - **Requirement**: Caller must provide valid structure pointer
   - **Violation Effect**: Undefined behavior (segmentation fault)
   - **Checking**: No explicit null check in function
   - **Assumption**: Caller validates parameter

2. **Initialized Token Array**: `sf->tokenvec` must be properly initialized
   - **Requirement**: Prior call to tokenization must have occurred
   - **Violation Effect**: Undefined token pattern matching
   - **Dependencies**: `libinjection_sqli_tokenize()` must have run

3. **Valid Current Pointer**: `sf->current` points to valid token
   - **Requirement**: Current pointer within tokenvec bounds
   - **Violation Effect**: Invalid memory access during tokenization
   - **Maintained**: By tokenization function

4. **Structure State Consistency**: Internal state must be coherent
   - **Requirement**: No corrupted position pointers or counts
   - **Violation Effect**: Infinite loops or buffer overruns
   - **Dependencies**: Previous libinjection operations succeeded

### Input Data Constraints
5. **Token Type Validity**: All token types must be valid enum values
   - **Requirement**: `sf->tokenvec[i].type` ∈ {valid TYPE_* constants}
   - **Violation Effect**: Pattern matching may fail unexpectedly
   - **Checking**: Implicit through enum comparison

6. **Token Length Consistency**: Token lengths match actual string lengths
   - **Requirement**: `sf->tokenvec[i].len` matches actual string data
   - **Violation Effect**: String operations may access invalid memory
   - **Critical Case**: Zero-length check for TYPE_EVIL detection

## 3. Postconditions

### Function Exit Guarantees
1. **Valid Return Count**: Return value indicates valid token count
   - **Guarantee**: `0 ≤ return_value ≤ LIBINJECTION_SQLI_MAX_TOKENS` (normal case)
   - **Exception**: `return_value > LIBINJECTION_SQLI_MAX_TOKENS` indicates error
   - **Established**: Final bounds clamping

2. **Token Array Consistency**: First `return_value` tokens are valid
   - **Guarantee**: `sf->tokenvec[0]` through `sf->tokenvec[return_value-1]` contain valid tokens
   - **Undefined**: Tokens beyond return value may be in undefined state
   - **Maintained**: Folding operations preserve token structure

3. **Folded Token Stream**: Output represents canonicalized input
   - **Guarantee**: Semantically equivalent to input but with reduced noise
   - **Preserved**: Essential SQL structure maintained
   - **Removed**: Comments, redundant operators, unnecessary parentheses

4. **Statistics Update**: Folding statistics reflect operations performed
   - **Guarantee**: `sf->stats_folds` incremented by actual folding count
   - **Accuracy**: Each folding operation counted exactly once
   - **Monotonic**: Never decreases from entry value

### Error Path Postconditions
5. **Error State Detection**: TYPE_EVIL tokens indicate parsing errors
   - **Guarantee**: When return > MAX_TOKENS, TYPE_EVIL token present
   - **Position**: Error token at position indicated by return value
   - **Recovery**: Calling code should abort processing

6. **Partial Processing State**: On error, partial results may be valid
   - **Guarantee**: Tokens processed before error remain valid
   - **Undefined**: Tokens at/after error position may be corrupted
   - **Statistics**: `sf->stats_folds` reflects work done up to error

### Global State Impact
7. **No External Side Effects**: Function modifies only provided structure
   - **Guarantee**: No global variable modifications
   - **Guarantee**: No file system or network operations
   - **Isolation**: Effects contained within `sf` structure

## 4. Loop Invariants

### Main Processing Loop Invariants
1. **Position Relationship**: `left ≤ pos` maintained throughout loop
   - **Entry**: True when loop begins
   - **Maintenance**: All operations preserve this relationship
   - **Exit**: Still true when loop terminates

2. **Token Validity**: Tokens `[0, left)` are finalized and valid
   - **Entry**: left = 0, so vacuously true
   - **Maintenance**: left only advances after successful processing
   - **Exit**: All tokens `[0, left)` represent final folded output

3. **Processing Window**: Active window is `[left, pos)`
   - **Entry**: Window starts empty (left = pos = 0)
   - **Maintenance**: Window expands with tokenization, contracts with advancement
   - **Exit**: Window represents final unprocessed tokens

4. **Buffer Bounds**: `pos ≤ LIBINJECTION_SQLI_MAX_TOKENS + 1`
   - **Entry**: pos = 0, bound satisfied
   - **Maintenance**: Tokenization loops enforce this bound
   - **Exit**: Ensures no buffer overrun occurred

### Tokenization Sub-loop Invariants
5. **Token Count Control**: `pos - left ≤ 3` during token gathering
   - **Entry**: Initially pos = left
   - **Maintenance**: Loop terminates when difference reaches limit
   - **Exit**: Never more than 3 tokens in processing window

6. **Comment Handling**: Comments don't increment pos but update `last_comment`
   - **Entry**: `last_comment.type = CHAR_NULL`
   - **Maintenance**: Comments saved but don't advance position
   - **Exit**: Last comment preserved for potential inclusion

### Folding Sub-process Invariants  
7. **Semantic Preservation**: Folding maintains SQL semantics
   - **Entry**: Token sequence represents valid SQL structure
   - **Maintenance**: Each folding rule preserves or improves semantics
   - **Exit**: Final sequence represents equivalent SQL

8. **Reduction Property**: Folding never increases token count
   - **Entry**: Initial token count from prior tokenization
   - **Maintenance**: All folding operations decrease count
   - **Exit**: Final count ≤ initial count

## 5. Memory Safety Properties

### Buffer Access Safety
1. **Token Array Bounds**: All accesses within allocated bounds
   - **Valid Range**: `sf->tokenvec[0]` through `sf->tokenvec[5]`
   - **Access Pattern**: Function accesses `[left]`, `[left+1]`, `[left+2]`
   - **Safety Condition**: `left + 2 ≤ 5` when accessing 3-token patterns
   - **Enforcement**: Loop bounds ensure safety

2. **Pointer Validity**: `sf->current` always points to valid memory
   - **Assignment**: `sf->current = &(sf->tokenvec[pos])`
   - **Safety Condition**: `pos ≤ 5` (within tokenvec bounds)
   - **Enforcement**: Position bounds checking

3. **String Access Safety**: Token string accesses within string bounds
   - **Access Pattern**: `sf->tokenvec[i].val[j]` where `j < sf->tokenvec[i].len`
   - **Safety Dependency**: Tokenization must set lengths correctly
   - **Critical Functions**: `cstrcasecmp()` calls rely on proper lengths

### Use-After-Free Prevention
4. **No Dynamic Allocation**: Function performs no memory allocation/deallocation
   - **Property**: All data structures provided by caller
   - **Safety**: No memory management errors possible
   - **Scope**: All variables are stack-allocated or structure members

5. **Token Lifetime**: Tokens remain valid throughout function execution
   - **Property**: Token data not freed or reallocated during processing
   - **Dependency**: Caller must maintain token storage
   - **Access Pattern**: Multiple accesses to same token data

### Buffer Overflow Prevention
6. **Copy Operations**: Token copy operations respect buffer boundaries
   - **Operation**: `st_copy(&dest, &src)` used for token copying
   - **Safety**: Copy function must respect token buffer sizes
   - **Assumption**: `st_copy()` implementation is memory-safe

7. **String Operations**: String comparisons respect string boundaries
   - **Function**: `cstrcasecmp()` with explicit length parameters
   - **Safety**: Length parameters prevent buffer overruns
   - **Pattern**: `cstrcasecmp(string, token.val, token.len)`

## 6. Implicit Contracts

### Caller Contracts
1. **Structure Initialization**: Caller must initialize `sf` structure properly
   - **Requirement**: All relevant fields set to valid initial values
   - **Dependency**: Prior successful tokenization pass
   - **Validation**: Function assumes caller has done this correctly

2. **Token Array Validity**: Caller provides sufficiently large token array
   - **Requirement**: `sf->tokenvec` must accommodate MAX_TOKENS + 1 entries
   - **Size**: Minimum 6 token entries required
   - **Usage**: Function may temporarily use position 5

3. **Single-Threaded Access**: Function not thread-safe
   - **Requirement**: Caller must ensure exclusive access to `sf`
   - **Modification**: Function modifies structure during execution
   - **Concurrency**: No protection against concurrent access

### Callee Contracts to Caller
4. **Structure Preservation**: Function preserves essential structure state
   - **Guarantee**: Core structure fields remain valid after execution
   - **Modification**: Only specific fields are intentionally modified
   - **Restoration**: No need for caller to reinitialize after normal return

5. **Error Indication**: Clear error signaling through return value
   - **Normal Return**: `0 ≤ return ≤ 5` indicates success
   - **Error Return**: `return > 5` indicates TYPE_EVIL encountered
   - **Details**: Error token placed in array for caller inspection

6. **Statistical Accuracy**: Folding statistics accurately maintained
   - **Guarantee**: `sf->stats_folds` incremented for each actual fold
   - **Precision**: Count reflects exact number of operations performed
   - **Usage**: Caller can use for performance metrics or debugging

### Inter-Function Contracts
7. **Tokenization Dependency**: Relies on `libinjection_sqli_tokenize()`
   - **Contract**: Tokenization function provides valid tokens
   - **State**: Tokenizer updates `sf->current` and advances position
   - **Cooperation**: Both functions share same state structure

8. **Utility Function Contracts**: Depends on helper functions
   - **`st_is_unary_op()`**: Must correctly identify unary operators
   - **`syntax_merge_words()`**: Must safely merge compatible tokens
   - **`st_copy()`**: Must safely copy token data between positions
   - **`cstrcasecmp()`**: Must perform safe case-insensitive comparison

### Global Environment Contracts
9. **Constant Definitions**: Relies on compile-time constants
   - **`LIBINJECTION_SQLI_MAX_TOKENS`**: Must equal 5
   - **`TYPE_*` Constants**: Must have stable, unique values
   - **String Constants**: Comparison strings must remain valid

10. **No External Dependencies**: Function is self-contained
    - **Guarantee**: No file system, network, or database access
    - **Isolation**: Effects limited to provided data structure
    - **Determinism**: Same input always produces same output