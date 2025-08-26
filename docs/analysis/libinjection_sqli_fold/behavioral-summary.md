# Behavioral Summary - libinjection_sqli_fold

**Function**: `int libinjection_sqli_fold(struct libinjection_sqli_state *sf)`  
**Location**: `libinjection-c/src/libinjection_sqli.c`  
**Analysis Date**: 2025-08-26  
**Analysis Phase**: Phase 1 Complete (Phases 1.1, 1.2, 1.3)

## Executive Summary

`libinjection_sqli_fold` is a **token stream reduction algorithm** that canonicalizes SQL injection attempts by eliminating obfuscation and normalizing equivalent SQL patterns. It serves as the critical **middle phase** of libinjection's three-phase detection pipeline: tokenize → **fold** → blacklist match.

The function processes a pre-tokenized SQL input and reduces it to a canonical form containing at most 5 tokens, enabling reliable pattern matching against known SQL injection fingerprints regardless of syntactic variations.

## Core Behavioral Specification  

### Input/Output Contract
- **Input**: Populated `libinjection_sqli_state` structure with tokenized SQL
- **Output**: Integer count of remaining tokens after folding (0-5 normal, >5 error)
- **Side Effects**: Modifies token array in-place, updates folding statistics

### Primary Algorithm
1. **Initial Skip Phase**: Skip comments, parentheses, SQL types, and unary operators
2. **Main Folding Loop**: Iteratively apply 2-token and 3-token folding rules
3. **Special Case Handling**: Handle specific 5-token patterns at capacity limit
4. **Cleanup**: Preserve final comment if space available, clamp token count

### Processing Model
- **Strategy**: Greedy left-to-right reduction with pattern-based rules
- **Complexity**: O(n) bounded by maximum token limit (constant time)
- **State Machine**: 7 primary states with deterministic transitions
- **Memory Model**: In-place modification of caller-provided token array

## Critical Implementation Requirements

### Mathematical Invariants (MUST PRESERVE)
1. **Position Ordering**: `left ≤ pos` at all times
2. **Token Bounds**: `pos ≤ LIBINJECTION_SQLI_MAX_TOKENS + 1` (≤ 6)
3. **Return Range**: `0 ≤ return_value ≤ 5` (normal), `> 5` (error)
4. **Processing Window**: `pos - left ≤ 3` during tokenization
5. **Monotonic Reduction**: Folding never increases token count

### Memory Safety Requirements (CRITICAL)
1. **Buffer Bounds**: All `tokenvec` accesses within `[0, 5]` range
2. **Pointer Validity**: `sf->current` always points to valid token
3. **String Safety**: Token string accesses respect length bounds
4. **No Dynamic Memory**: Function performs no allocation/deallocation

### Functional Requirements (ESSENTIAL)
1. **Semantic Preservation**: Folding maintains SQL structural meaning
2. **Pattern Recognition**: Must handle all specified 2-token and 3-token patterns
3. **Error Detection**: Detect and mark TYPE_EVIL conditions appropriately
4. **Statistics Accuracy**: Maintain precise fold operation count

## Folding Rule Categories

### Two-Token Folding Rules
- **String Concatenation**: `"foo" "bar" → "foo"`
- **Semicolon Deduplication**: `; ; → ;`
- **Operator-Unary Elimination**: `OPERATOR UNARY → OPERATOR`
- **Parenthesis-Unary Simplification**: `( UNARY → (`
- **Word Merging**: Merge compatible SQL keywords
- **Function Type Conversion**: Convert barewords to functions with parentheses
- **Keyword Context Conversion**: Convert IN/LIKE based on following tokens
- **SQL Type Elimination**: Remove SQL types in certain contexts
- **Collation Handling**: Handle COLLATE followed by identifiers
- **Backslash Processing**: Handle TSQL backslash escape sequences
- **Parenthesis Deduplication**: `( ( → (`, `) ) → )`
- **MySQL Brace Handling**: Process `{ bareword` patterns
- **Brace Closing**: Remove closing braces

### Three-Token Folding Rules  
- **Arithmetic Expressions**: `NUMBER OPERATOR NUMBER → NUMBER`
- **Operator Sequences**: `OPERATOR [not (] OPERATOR → OPERATOR`
- **Logic Sequences**: `LOGIC_OP * LOGIC_OP → LOGIC_OP`
- **Variable Expressions**: Handle variable-operator-value patterns
- **Bareword Expressions**: Process bareword-operator-value patterns
- **Type Casting**: Handle `value :: SQLTYPE` PostgreSQL syntax
- **Comma Lists**: Process comma-separated value lists
- **Unary Expression Simplification**: Remove unary operators in expressions
- **Dot Notation**: Handle `bareword.bareword` database.table references
- **Function Validation**: Validate zero-argument functions like USER()

### Special Five-Token Handling
Four specific patterns recognized when token limit reached:
1. `NUMBER (OPERATOR|COMMA) ( NUMBER )`
2. `BAREWORD OPERATOR ( (BAREWORD|NUMBER) )`  
3. `NUMBER ) , ( NUMBER`
4. `BAREWORD ) OPERATOR ( BAREWORD`

## Error Conditions and Recovery

### TYPE_EVIL Detection
- **Trigger**: Zero-length bareword token in MySQL brace context
- **Response**: Set `tokenvec[pos].type = TYPE_EVIL`, return `pos + 2`
- **Interpretation**: Unparseable input, caller should abort processing

### Resource Exhaustion
- **Token Limit**: Processing stops when 5-token limit reached
- **Overflow Handling**: Temporary use of 6th token position for lookahead
- **Recovery**: Reset to valid state or apply special patterns

### Logic Error Prevention
- **Bounds Checking**: Position variables constrained by loop conditions
- **State Validation**: Invariants prevent infinite loops and corruption
- **Graceful Degradation**: Function continues processing despite minor issues

## Integration Points

### Upstream Dependencies
- **`libinjection_sqli_tokenize()`**: Provides raw token stream
- **Token State Structure**: Must be properly initialized
- **Helper Functions**: `st_is_unary_op()`, `syntax_merge_words()`, `st_copy()`

### Downstream Consumers
- **`libinjection_sqli_blacklist()`**: Matches folded patterns against fingerprints
- **Fingerprint Generation**: Folded tokens become detection signature
- **Statistical Analysis**: Folding metrics used for performance tuning

### Threading and Concurrency
- **Thread Safety**: NOT thread-safe, requires external synchronization
- **State Isolation**: All state contained in caller-provided structure
- **Reentrancy**: Safe for recursive calls with separate state structures

## Performance Characteristics

### Time Complexity
- **Average Case**: O(1) - bounded by maximum token limit
- **Worst Case**: O(1) - same bound applies
- **Token Limit**: Maximum 5 output tokens, ~10-20 folding operations typical

### Space Complexity
- **Memory Usage**: O(1) - fixed-size token array (6 entries)
- **Stack Usage**: O(1) - minimal local variables
- **No Allocation**: Zero dynamic memory allocation

### Optimization Opportunities
- **Pattern Order**: Most common folding patterns checked first
- **Early Termination**: Empty input detected quickly
- **Special Cases**: Optimized handling of common 5-token scenarios

## Rust Implementation Guidance

### Memory Management
- Replace C-style pointer arithmetic with safe Rust array indexing
- Use Rust's bounds checking to eliminate buffer overrun risks
- Consider `Vec<Token>` vs fixed-size array trade-offs

### Type Safety
- Convert C enums to Rust enums with exhaustive matching
- Use type system to enforce token count bounds
- Consider newtype wrappers for position indices

### Error Handling
- Replace C-style error codes with Result<usize, FoldError>
- Use Rust's panic safety for invariant violations
- Consider structured error types for different failure modes

### Performance Considerations
- Profile against C implementation for performance parity
- Consider zero-allocation approaches using array manipulation
- Benchmark different token storage strategies

### Safety Guarantees
- Eliminate undefined behavior through Rust's safety system
- Use safe abstractions for token copying and manipulation
- Ensure all invariants are compile-time or runtime-enforced

## Testing Strategy Requirements

### Comprehensive Coverage
- Test all 2-token and 3-token folding rules individually
- Test combinations and interactions between rules
- Test special 5-token scenarios and overflow handling

### Edge Cases
- Empty input streams and single-token inputs
- Maximum-length token sequences
- TYPE_EVIL triggering conditions
- Boundary conditions for all numeric limits

### Property-Based Testing
- Verify mathematical invariants hold across all executions
- Test that folding never increases token count
- Validate that return value accurately reflects output length
- Ensure semantic equivalence between input and output

### Integration Testing
- Test with real SQL injection samples
- Verify compatibility with upstream tokenization
- Validate downstream fingerprint matching works correctly

This behavioral specification provides the complete foundation needed for accurate Rust implementation while maintaining full compatibility with the original C function's behavior.