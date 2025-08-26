# Function Analysis Template

Use this template for each function analysis to ensure consistency.

## Function: `[FUNCTION_NAME]`
**File**: `[FILE_PATH]`  
**Lines**: `[START_LINE]-[END_LINE]`  
**Analysis Date**: `[DATE]`

---

## Phase 1.1: Algorithmic Understanding

### High-Level Behavioral Flowchart
```
[Insert flowchart or detailed description of control flow]
```

### State Machine Analysis
- **Is this a state machine?**: [Yes/No]
- **States**: [List all states if applicable]
- **Transitions**: [State transition table]
- **Initial state**: [Starting state]
- **Final states**: [End states]

### Execution Path Enumeration
1. **Path 1**: [Entry conditions → Operations → Exit conditions]
2. **Path 2**: [Entry conditions → Operations → Exit conditions]
3. [Continue for all paths...]

### Function Purpose Analysis
- **Core Algorithm**: [What algorithm is implemented?]
- **Problem Solved**: [What problem does this solve?]
- **Key Invariants**: [What properties are maintained?]
- **Architectural Role**: [How does it fit in libinjection?]

---

## Phase 1.2: Data Flow Analysis

### Input Analysis
| Parameter | Type | Constraints | Null Handling | Range |
|-----------|------|-------------|---------------|-------|
| [param1] | [type] | [constraints] | [behavior] | [range] |

### Buffer Manipulation Sequences
1. **Buffer Operations**: [List all buffer reads/writes in order]
2. **Pointer Arithmetic**: [Document all pointer calculations]
3. **Bounds Checking**: [Where bounds are checked or assumed]

### State Variable Modifications
| Variable | Type | Initial Value | Modifications | Final Value |
|----------|------|---------------|---------------|-------------|
| [var1] | [type] | [initial] | [how changed] | [final] |

### Output Generation Logic
- **Return Value**: [How computed?]
- **Output Parameters**: [How populated?]
- **Side Effects**: [Global state changes, etc.]

### Error Propagation Paths
- **Error Detection**: [How are errors found?]
- **Error Reporting**: [Return codes, errno, etc.]
- **Cleanup**: [What cleanup on error?]
- **Resource Leaks**: [Any possible leaks?]

---

## Phase 1.3: Invariant Discovery

### Mathematical Relationships
- **Invariant 1**: [Mathematical expression] - [Description]
- **Invariant 2**: [Mathematical expression] - [Description]
- [Continue for all relationships...]

### Preconditions
- **Required State**: [What must be true at function entry?]
- **Parameter Constraints**: [Valid parameter ranges]
- **Global Assumptions**: [Required global state]

### Postconditions
- **Guaranteed State**: [What is guaranteed at exit?]
- **Return Value Meaning**: [What each return value means]
- **Global State Changes**: [How global state is modified]

### Loop Invariants
For each loop:
- **Loop [N]**: [What stays constant during iterations?]
- **Entry Condition**: [State at loop start]
- **Exit Condition**: [State at loop end]
- **Termination**: [What guarantees termination?]

### Memory Safety Properties
- **Valid Pointers**: [Which pointers are guaranteed valid?]
- **Buffer Bounds**: [What bounds are maintained?]
- **Lifetime**: [Object lifetime guarantees]

### Implicit Contracts
- **Caller Assumptions**: [What function assumes about callers]
- **Caller Guarantees**: [What function guarantees to callers]
- **Inter-function Dependencies**: [How it relates to other functions]

---

## Edge Cases Identified

### Boundary Conditions
- [ ] Empty input (length 0)
- [ ] NULL pointers  
- [ ] Maximum size input
- [ ] Single character input
- [ ] Buffer boundary cases

### Error Conditions  
- [ ] Invalid UTF-8
- [ ] Malformed input
- [ ] Resource exhaustion
- [ ] Integer overflow
- [ ] [Other specific error cases]

---

## Implementation Notes

### Critical Behaviors to Preserve
1. [Behavior 1 that must be exactly preserved]
2. [Behavior 2 that must be exactly preserved]
3. [Continue...]

### Rust Translation Challenges
- **Challenge 1**: [Specific difficulty] → [Proposed approach]
- **Challenge 2**: [Specific difficulty] → [Proposed approach]

### Verification Strategy
- **Property Tests**: [What properties to test]
- **Edge Case Tests**: [Specific edge cases to verify]
- **Differential Tests**: [How to compare with C]

---

## Behavioral Summary

**In one paragraph**: [Summarize the complete behavior of this function]

**Key Properties**: [List the 3-5 most critical properties that must be preserved]

**Complexity**: [Algorithmic complexity analysis]

**Dependencies**: [What other functions/state this depends on]