# Phase 1.1: Algorithmic Understanding - libinjection_sqli_fold

**Function Location**: `libinjection-c/src/libinjection_sqli.c`  
**Function Signature**: `int libinjection_sqli_fold(struct libinjection_sqli_state *sf)`

## 1. High-Level Behavioral Flowchart

```
┌─────────────────────┐
│ START               │
│ sf->current = &(sf->tokenvec[0]) │
│ pos=0, left=0      │
│ more=1             │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ INITIAL_SKIP_PHASE  │
│ Skip comments,      │
│ left parens,        │
│ sqltypes, unary ops │
└──────────┬──────────┘
           │
           ▼
        ┌─────┐  yes  ┌─────────────────┐
        │more?├─────► │ return 0        │
        └──┬──┘       │ (empty input)   │
           │no        └─────────────────┘
           ▼
┌─────────────────────┐
│ pos += 1            │
│ (first real token)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ MAIN_FOLDING_LOOP   │
│ while (1)           │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │pos >= MAX_   ├─────► │ SPECIAL_5_TOKEN     │
    │TOKENS?       │       │ HANDLING            │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │!more ||      ├─────► │ left = pos; break   │
    │left>=MAX?    │       │ (TERMINATION)       │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
┌─────────────────────┐
│ TOKENIZE_2_TOKENS   │
│ Get up to 2 tokens  │
│ while skipping      │
│ comments            │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │pos-left < 2? ├─────► │ left = pos;         │
    │              │       │ continue            │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
┌─────────────────────┐
│ TWO_TOKEN_FOLDING   │
│ Apply 2-token       │
│ folding rules       │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │Folding rule  ├─────► │ Apply fold & continue│
    │matched?      │       │ (pos--, stats++)    │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
┌─────────────────────┐
│ TOKENIZE_3RD_TOKEN  │
│ Get one more token  │
│ (total of 3)        │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │pos-left < 3? ├─────► │ left = pos;         │
    │              │       │ continue            │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
┌─────────────────────┐
│ THREE_TOKEN_FOLDING │
│ Apply 3-token       │
│ folding rules       │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐  yes  ┌─────────────────────┐
    │Folding rule  ├─────► │ Apply fold & continue│
    │matched?      │       │ (pos-=2, left=0)    │
    └──────┬───────┘       └─────────────────────┘
           │no
           ▼
┌─────────────────────┐
│ left += 1           │
│ (advance to next    │
│ token)              │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ LOOP BACK TO        │
│ MAIN_FOLDING_LOOP   │
└─────────────────────┘
           ┌───────────────────┐
           ▼                   │
    ┌──────────────┐          │
    │ CLEANUP      │          │
    │ Add last     │          │
    │ comment back │          │
    │ if space     │          │
    └──────┬───────┘          │
           │                  │
           ▼                  │
    ┌──────────────┐          │
    │ RETURN left  │──────────┘
    │ (final count)│
    └──────────────┘
```

## 2. State Machine Analysis

**State Machine Type**: Token Processing Finite State Machine

**Primary States:**

1. **INITIAL_SKIP** - Skip initial uninteresting tokens
2. **WAITING_FOR_TOKENS** - Gathering tokens for folding analysis  
3. **TWO_TOKEN_ANALYSIS** - Analyzing and potentially folding 2-token patterns
4. **THREE_TOKEN_ANALYSIS** - Analyzing and potentially folding 3-token patterns
5. **ADVANCE_POSITION** - Move to next token when no folding occurs
6. **SPECIAL_FIVE_TOKEN** - Handle edge cases at token limit
7. **TERMINATED** - Final cleanup and return

**State Transition Table:**

| Current State | Input Condition | Next State | Action |
|---------------|----------------|------------|--------|
| INITIAL_SKIP | more=1, token is comment/paren/sqltype/unary | INITIAL_SKIP | Continue tokenizing |
| INITIAL_SKIP | more=0 | TERMINATED | return 0 |
| INITIAL_SKIP | more=1, token is other | WAITING_FOR_TOKENS | pos=1 |
| WAITING_FOR_TOKENS | pos >= MAX_TOKENS | SPECIAL_FIVE_TOKEN | Special handling |
| WAITING_FOR_TOKENS | !more \|\| left >= MAX_TOKENS | TERMINATED | left=pos, break |
| WAITING_FOR_TOKENS | pos-left < 2 | TWO_TOKEN_ANALYSIS | Get 2 tokens |
| TWO_TOKEN_ANALYSIS | pos-left < 2 | WAITING_FOR_TOKENS | left=pos, continue |
| TWO_TOKEN_ANALYSIS | 2-token rule matches | WAITING_FOR_TOKENS | Apply fold, continue |
| TWO_TOKEN_ANALYSIS | no rule matches | THREE_TOKEN_ANALYSIS | Get 3rd token |
| THREE_TOKEN_ANALYSIS | pos-left < 3 | WAITING_FOR_TOKENS | left=pos, continue |
| THREE_TOKEN_ANALYSIS | 3-token rule matches | WAITING_FOR_TOKENS | Apply fold, continue |
| THREE_TOKEN_ANALYSIS | no rule matches | ADVANCE_POSITION | left += 1 |
| ADVANCE_POSITION | always | WAITING_FOR_TOKENS | Continue loop |
| SPECIAL_FIVE_TOKEN | Special patterns found | WAITING_FOR_TOKENS | Reset pos/left |
| SPECIAL_FIVE_TOKEN | No special pattern | WAITING_FOR_TOKENS | Continue normally |

**Unreachable States**: None - all states are reachable through normal execution paths.

## 3. Execution Path Enumeration

### Path 1: Empty Input (Early Termination)
- **Entry**: Input contains only comments, parentheses, sqltypes, unary operators
- **Operations**: Initial skip phase consumes all tokens
- **Variables**: pos=0, left=0, more=0
- **Exit**: return 0

### Path 2: Single Token Input  
- **Entry**: Input has one meaningful token after initial skip
- **Operations**: pos=1, main loop entry, immediate termination due to pos-left<2
- **Variables**: pos=1, left=1
- **Exit**: return 1

### Path 3: Two Token Input with Folding
- **Entry**: Two tokens that match a folding rule
- **Operations**: Get 2 tokens, apply folding rule, pos decreases, continue
- **Variables**: pos varies, left resets to 0, stats_folds increases
- **Exit**: return final token count

### Path 4: Two Token Input without Folding
- **Entry**: Two tokens with no matching folding rule  
- **Operations**: Get 2 tokens, no fold, get 3rd token fails, advance left
- **Variables**: pos=2, left advances to 2
- **Exit**: return 2

### Path 5: Complex Multi-Token Folding
- **Entry**: Multiple tokens with various folding opportunities
- **Operations**: Multiple rounds of 2-token and 3-token folding
- **Variables**: pos and left change throughout, stats_folds accumulates
- **Exit**: return final count ≤ MAX_TOKENS

### Path 6: Five Token Special Cases
- **Entry**: Input generates exactly 5 tokens matching special patterns
- **Operations**: Special pattern recognition and restructuring
- **Variables**: pos and left reset according to special rules
- **Exit**: return reduced token count

### Path 7: Maximum Token Limit Reached
- **Entry**: Input would generate > MAX_TOKENS tokens
- **Operations**: Processing limited to MAX_TOKENS, potential special handling
- **Variables**: left capped at MAX_TOKENS
- **Exit**: return MAX_TOKENS

## 4. Function Purpose Analysis

### Core Algorithm
The `libinjection_sqli_fold` function implements a **multi-pass token stream reduction algorithm** that consolidates SQL tokens into a canonical form for fingerprint matching.

### Problem Being Solved
**SQL Injection Detection via Syntax Normalization**: Raw SQL injection attempts often use various obfuscation techniques (extra spaces, comments, redundant operators, etc.). This function normalizes these variations into a consistent token pattern that can be matched against known attack fingerprints.

### Key Invariants Maintained
1. **Token Count Constraint**: Final output never exceeds `LIBINJECTION_SQLI_MAX_TOKENS` (5)
2. **Semantic Preservation**: Folding rules preserve the essential SQL structure while removing noise
3. **Left-to-Right Processing**: Tokens are processed and consolidated from left to right
4. **Comment Preservation**: Last comment token is preserved if space permits
5. **Monotonic Reduction**: Total token count never increases, only decreases or stays same

### Relationship to Overall Architecture
This function is the **second phase** of libinjection SQL detection:

1. **Phase 1**: `libinjection_sqli_tokenize()` - Breaks input into raw tokens
2. **Phase 2**: `libinjection_sqli_fold()` - **THIS FUNCTION** - Reduces tokens to canonical form  
3. **Phase 3**: `libinjection_sqli_blacklist()` - Matches folded pattern against attack signatures

The folding phase is **critical** because it:
- Eliminates noise and obfuscation attempts
- Standardizes equivalent SQL patterns  
- Reduces the search space for pattern matching
- Enables reliable detection despite syntax variations

### Algorithmic Classification
- **Type**: Multi-pass pattern recognition and reduction
- **Complexity**: O(n) where n is input token count (bounded by MAX_TOKENS)
- **Strategy**: Greedy left-to-right folding with backtracking capability
- **Pattern**: State machine with look-ahead and context-sensitive rules