# Phase 1.2: Data Flow Analysis - libinjection_sqli_tokenize

## Function Signature Analysis
```c
int libinjection_sqli_tokenize(struct libinjection_sqli_state *sf)
```

## 1. Input Analysis

### Primary Input Parameter
**Parameter**: `struct libinjection_sqli_state *sf`
- **Type**: Pointer to parsing state structure
- **Expected Range**: Must be valid, non-NULL pointer
- **Constraints**: Must be properly initialized via `libinjection_sqli_init()`
- **NULL Handling**: No explicit NULL check - undefined behavior if NULL

### Key Input Fields (from sf structure)
1. **`sf->s`** (const char *) - Input string to tokenize
   - **Range**: Can be NULL if slen == 0
   - **Constraints**: Does not need to be null-terminated
   - **Usage**: Read-only access for character lookup

2. **`sf->slen`** (size_t) - Length of input string
   - **Range**: 0 to SIZE_MAX
   - **Constraints**: Must accurately reflect string length
   - **Special**: slen == 0 triggers immediate FALSE return

3. **`sf->pos`** (size_t) - Current position in string
   - **Range**: 0 to slen (inclusive)
   - **Constraints**: Must be <= slen
   - **Usage**: Read and modified throughout function

4. **`sf->flags`** (int) - Parsing behavior flags
   - **Range**: Bitfield of FLAG_* constants
   - **Constraints**: FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE affect initial parsing
   - **Usage**: Checked for quote context at position 0

5. **`sf->current`** (stoken_t *) - Current token being built
   - **Range**: Must point to valid token structure
   - **Constraints**: Should point to sf->tokenvec element
   - **Usage**: Cleared and populated during parsing

### Implicit Inputs
1. **Global lookup table**: `char_parse_map[]` - 256-entry function pointer array
2. **Character parsers**: Functions like `parse_string`, `parse_number`, etc.
3. **Helper functions**: `st_clear`, `flag2delim`, `parse_string_core`

## 2. Buffer Manipulation Sequences

### Primary Buffer: Input String (`sf->s`)
```
Read Pattern: sf->s[sf->pos] 
Buffer Access: Single character read via array indexing
Bounds Checking: Loop condition `pos < slen` prevents overrun
Position Updates: `sf->pos` updated by character parsers
```

### Position Tracking Sequence
```c
1. size_t *pos = &sf->pos;              // Create position pointer
2. while (*pos < slen) {                // Bounds check
3.   const unsigned char ch = s[*pos];  // Read character
4.   *pos = (*fnptr)(sf);              // Parser updates position
5. }
```

### Token Buffer: `sf->current`
```
Write Pattern: Various fields modified by parsers
Buffer Layout: Fixed-size structure (stoken_t)
Safety: No bounds checking on token internal buffers
Memory: Stack-allocated structure, no dynamic allocation
```

### Critical Buffer Operations
1. **Character Read**: `s[*pos]` - Protected by loop bounds check
2. **Position Update**: Modified by parser functions - **potential overrun risk**
3. **Token Write**: Parsers populate `sf->current` fields - **potential overflow in val[32]**

## 3. State Variable Modifications

### Local Variables
| Variable | Type | Lifetime | Purpose | Modifications |
|----------|------|----------|---------|---------------|
| `fnptr` | `pt2Function` | Function scope | Parser function pointer | Set once per character |
| `pos` | `size_t *` | Function scope | Position pointer alias | Points to `sf->pos`, indirect updates |
| `current` | `stoken_t *` | Function scope | Token pointer alias | Points to `sf->current`, no direct updates |
| `s` | `const char *` | Function scope | String pointer alias | Read-only, no updates |
| `slen` | `size_t` | Function scope | Length alias | Read-only, no updates |

### Modified State Fields
1. **`sf->pos`** 
   - **Initial**: Existing value (0 for fresh parsing)
   - **Updates**: Set by character parser functions
   - **Final**: Points to next unprocessed character or end of string

2. **`sf->current`** (token fields)
   - **Initial**: Cleared via `st_clear()`
   - **Updates**: Populated by character parsers if token found
   - **Final**: Contains complete token or remains cleared

3. **`sf->stats_tokens`**
   - **Initial**: Existing count
   - **Updates**: Incremented by 1 when token is found
   - **Final**: Original count + 1 or unchanged

### State Dependencies
```
sf->pos → determines which character is processed
sf->current → populated based on character at sf->pos
sf->stats_tokens → incremented based on sf->current->type
char_parse_map[ch] → determines which parser modifies sf->pos
```

## 4. Output Generation Logic

### Return Value Logic
```c
Return TRUE when:
1. Quote context: pos == 0 && (flags & quote_flags) → parse initial string
2. Token found: current->type != CHAR_NULL after parser call

Return FALSE when:
1. Empty input: slen == 0
2. End of input: pos >= slen with no token found
```

### Output Parameters
**Primary**: `sf->current` populated with token data:
- `pos`: Start position in original string
- `len`: Token length  
- `type`: Token type character
- `val`: Token value string
- `count`: Context-dependent counter
- `str_open`/`str_close`: Quote characters for strings

**Secondary**: `sf->pos` updated to next parsing position

### Side Effects
1. **Statistics**: `sf->stats_tokens` incremented
2. **State**: `sf->current` modified (cleared then optionally populated)
3. **Position**: `sf->pos` advanced by character parser

## 5. Error Propagation Paths

### Error Detection Methods
1. **Input validation**: `slen == 0` check
2. **Loop termination**: `pos < slen` prevents infinite loops
3. **Token validation**: `current->type != CHAR_NULL` indicates success

### Error Reporting
- **Return value**: FALSE indicates no token found or error
- **No errno**: Function doesn't set system error codes
- **No exceptions**: Pure C function, no exception handling

### Error Scenarios
1. **Empty Input**
   - **Detection**: `slen == 0`
   - **Response**: Immediate FALSE return
   - **Cleanup**: None needed

2. **End of Input Reached**
   - **Detection**: Loop exits with `pos >= slen`
   - **Response**: FALSE return
   - **Cleanup**: None needed

3. **Parser Failure**
   - **Detection**: Parser returns without setting token type
   - **Response**: Continue parsing or return FALSE at end
   - **Cleanup**: Token remains cleared

### Resource Management
- **No dynamic allocation**: All data is in provided structure
- **No cleanup required**: No resources acquired
- **No leak potential**: Stack-based local variables only

## Data Flow Diagram

```
INPUT FLOW:
sf (state) → Local aliases → Character dispatch → Parser functions

PROCESSING FLOW:  
sf->s[sf->pos] → char_parse_map[ch] → parser_function(sf) → sf->current + sf->pos

OUTPUT FLOW:
sf->current (populated) → return TRUE
sf->stats_tokens (incremented) → side effect
sf->pos (advanced) → state update

ERROR FLOW:
slen == 0 → return FALSE
pos >= slen → return FALSE  
current->type == CHAR_NULL → continue loop or return FALSE
```

## Critical Data Flow Properties
1. **Position Monotonicity**: `sf->pos` only increases or stays same
2. **Single Token**: At most one token produced per call
3. **State Preservation**: Failed parsing doesn't corrupt state
4. **Memory Safety**: No dynamic allocation, bounded stack usage