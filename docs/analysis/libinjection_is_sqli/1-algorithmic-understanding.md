# Function Analysis: libinjection_is_sqli

**File**: `libinjection-c/src/libinjection_sqli.c`  
**Lines**: `2244-2316`  
**Analysis Date**: `2025-08-26`

---

## Phase 1.1: Algorithmic Understanding

### High-Level Behavioral Flowchart

```
START: libinjection_is_sqli(sql_state)
  |
  v
Extract s = sql_state->s, slen = sql_state->slen
  |
  v
[Check: slen == 0?]
  |           |
  YES         NO
  |           |
  v           v
Return FALSE  Test input "as-is" with ANSI SQL flags
              |
              v
            Generate fingerprint with FLAG_QUOTE_NONE | FLAG_SQL_ANSI
              |
              v
            [Lookup fingerprint in blacklist]
              |           |
              FOUND       NOT FOUND
              |           |
              v           v
            Return TRUE   [Check: reparse_as_mysql()?]
                          |           |
                          YES         NO
                          |           |
                          v           v
                        Reparse with   Check single quote
                        MySQL flags    |
                        |             v
                        v           [memchr(s, '\'', slen)?]
                      [Lookup?]       |           |
                        |           YES         NO
                        v           |           |
                    [FOUND/NOT]     v           v
                      |           Test with     Check double quote
                    Return         single       |
                    TRUE/FALSE     quote        v
                                  context      [memchr(s, '"', slen)?]
                                    |           |           |
                                    v           YES         NO
                                [ANSI test]     |           |
                                    |           v           v
                                    v         Test with    Return FALSE
                                [MySQL test]  double       (No SQLi detected)
                                    |         quote
                                    v         context
                                Return        |
                                TRUE/FALSE    v
                                            [MySQL test only]
                                              |
                                              v
                                            Return
                                            TRUE/FALSE
```

### State Machine Analysis

- **Is this a state machine?**: No
- **Analysis**: This is a sequential decision tree function, not a state machine. The function processes input through a fixed sequence of testing contexts without maintaining state transitions between calls.

### Execution Path Enumeration

1. **Path 1 - Empty Input**: 
   - Entry: `slen == 0`
   - Operations: None
   - Exit: `return FALSE`

2. **Path 2 - ANSI Match (As-Is)**:
   - Entry: `slen > 0`
   - Operations: Generate fingerprint with `FLAG_QUOTE_NONE | FLAG_SQL_ANSI`, lookup in blacklist
   - Exit: `return TRUE` if fingerprint found

3. **Path 3 - MySQL Match (As-Is)**:
   - Entry: `slen > 0`, ANSI failed, `reparse_as_mysql()` returns true
   - Operations: Generate fingerprint with `FLAG_QUOTE_NONE | FLAG_SQL_MYSQL`, lookup in blacklist
   - Exit: `return TRUE` if fingerprint found

4. **Path 4 - Single Quote ANSI Match**:
   - Entry: `slen > 0`, as-is tests failed, `memchr(s, '\'', slen)` found single quote
   - Operations: Generate fingerprint with `FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI`, lookup in blacklist
   - Exit: `return TRUE` if fingerprint found

5. **Path 5 - Single Quote MySQL Match**:
   - Entry: Same as Path 4, ANSI failed, `reparse_as_mysql()` returns true
   - Operations: Generate fingerprint with `FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL`, lookup in blacklist
   - Exit: `return TRUE` if fingerprint found

6. **Path 6 - Double Quote MySQL Match**:
   - Entry: `slen > 0`, previous tests failed, `memchr(s, '"', slen)` found double quote
   - Operations: Generate fingerprint with `FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL`, lookup in blacklist
   - Exit: `return TRUE` if fingerprint found

7. **Path 7 - Clean Input**:
   - Entry: All previous tests failed
   - Operations: None
   - Exit: `return FALSE`

### Function Purpose Analysis

- **Core Algorithm**: Multi-context SQL injection detection using fingerprinting technique
- **Problem Solved**: Determines if input string contains SQL injection patterns by testing it in multiple SQL parsing contexts (no quotes, single quotes, double quotes) and dialect variations (ANSI vs MySQL)
- **Key Invariants**: 
  - Always tests input in order: as-is → single-quote → double-quote contexts
  - ANSI SQL parsing is attempted before MySQL parsing when conditions warrant
  - Function returns immediately upon first positive match (short-circuit evaluation)
- **Architectural Role**: 
  - Main entry point for SQL injection detection in libinjection
  - Orchestrates the fingerprinting process by testing multiple contexts
  - Leverages `libinjection_sqli_fingerprint()` for actual parsing and `lookup()` callback for pattern matching
  - Uses `reparse_as_mysql()` heuristic to determine when MySQL-specific parsing is needed