# Phase 1.1: Algorithmic Understanding - libinjection_sqli_blacklist

## Function Purpose
`libinjection_sqli_blacklist` determines whether a SQL fingerprint pattern matches known SQL injection attack patterns. It serves as the core pattern-matching component of the libinjection SQLi detection system.

## High-Level Behavioral Flowchart

```
Input: sql_state (contains fingerprint string)
  |
  v
Check if fingerprint length < 1
  |-- YES --> Set reason, Return FALSE
  |
  v
NO: Convert fingerprint to v1 format:
  - Add '0' prefix
  - Convert lowercase to uppercase
  |
  v
Search fingerprint in keyword database
using is_keyword(fingerprint) == TYPE_FINGERPRINT
  |
  v-- NO MATCH --> Set reason, Return FALSE
  |
  v
MATCH FOUND --> Return TRUE
```

## Execution Path Enumeration

### Path 1: Empty/Invalid Fingerprint
- **Condition**: `len < 1` (where len = strlen(sql_state->fingerprint))
- **Actions**: 
  - Set `sql_state->reason = __LINE__` (line 1987)
  - Return `FALSE`
- **Probability**: Low in normal operation (fingerprints are generated before this call)

### Path 2: Valid Fingerprint, No Pattern Match
- **Condition**: `len >= 1` AND `is_keyword(fp2, len + 1) != TYPE_FINGERPRINT`
- **Actions**:
  - Convert fingerprint to v1 format (add '0' prefix, uppercase)
  - Perform binary search in keyword database
  - Set `sql_state->reason = __LINE__` (line 2017)
  - Return `FALSE`
- **Probability**: High for benign SQL patterns

### Path 3: Valid Fingerprint, Pattern Match Found
- **Condition**: `len >= 1` AND `is_keyword(fp2, len + 1) == TYPE_FINGERPRINT`
- **Actions**:
  - Convert fingerprint to v1 format
  - Perform binary search in keyword database
  - Return `TRUE`
- **Probability**: Low but critical for SQLi detection

## State Machine Analysis

The function operates as a simple state machine with three states:

1. **VALIDATION**: Check fingerprint validity (length > 0)
2. **TRANSFORMATION**: Convert fingerprint format (v0 → v1)
3. **LOOKUP**: Binary search in fingerprint database

State transitions are deterministic and linear (no loops or complex branching).

## Algorithm Complexity

- **Time Complexity**: O(n + log m) where:
  - n = fingerprint length (typically ≤ 5 characters)
  - m = size of fingerprint database
- **Space Complexity**: O(1) - fixed 8-byte buffer for format conversion
- **Database Dependency**: Function relies on precompiled fingerprint database

## Version Compatibility Handling

The function handles backward compatibility between fingerprint formats:
- **v0 format**: Up to 5 characters, mixed case
- **v1 format**: '0' prefix + up to 5 characters, uppercase

This conversion ensures compatibility with existing fingerprint databases while supporting format evolution.

## Critical Dependencies

1. **is_keyword()**: Binary search function for fingerprint lookup
2. **sql_keywords database**: Precompiled fingerprint patterns with TYPE_FINGERPRINT markers
3. **strlen()**: Standard C library function for string length calculation
4. **__LINE__**: Compiler macro for debugging line numbers

## Error Handling Strategy

- **Debugging Support**: Sets `sql_state->reason` to specific line numbers for failure tracking
- **Graceful Degradation**: Returns FALSE for invalid inputs rather than crashing
- **No Exception Handling**: Uses C-style error codes (boolean return)

## Performance Characteristics

- **Best Case**: O(log m) - direct fingerprint match
- **Worst Case**: O(log m) - fingerprint not found after full binary search
- **Memory Access Pattern**: Sequential for conversion, logarithmic for lookup
- **Cache Efficiency**: Good due to small working set and binary search locality