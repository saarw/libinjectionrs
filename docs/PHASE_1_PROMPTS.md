# Phase 1: Deep C Code Analysis Prompts

These prompts are designed to force systematic behavioral analysis before any Rust implementation begins.

## Phase 1.1: Algorithmic Understanding Prompt

```
CRITICAL: Do NOT write any Rust code. Do NOT create test cases. Your task is pure analysis.

Analyze the C function `[FUNCTION_NAME]` in `[FILE_PATH]` and create a complete behavioral specification.

### Required Deliverables:

1. **High-Level Behavioral Flowchart**
   - Create a visual flowchart showing all major decision points
   - Include all loops, conditionals, and function calls
   - Show how control flows through the entire function
   - Mark all possible exit points and their conditions

2. **State Machine Analysis** (if applicable)
   - Identify if this function implements a state machine
   - If yes, enumerate all possible states
   - Create a complete state transition table
   - Show what inputs cause each transition
   - Identify any unreachable states or transitions

3. **Execution Path Enumeration**
   - List every possible path through the function
   - For each path, specify:
     - Entry conditions required
     - Operations performed
     - Variables modified
     - Exit conditions
   - Identify any paths that cannot be reached

4. **Function Purpose Analysis**
   - What is the core algorithm this function implements?
   - What problem is it solving?
   - What are the key invariants it maintains?
   - How does it relate to the overall libinjection architecture?

### Analysis Requirements:
- Read through the ENTIRE function before starting analysis
- Trace through complex conditional logic step by step  
- Don't assume anything - verify every branch
- Pay special attention to pointer arithmetic and buffer bounds
- Note any undefined behavior or potential bugs in the original C

### Output Format:
Write your analysis as a structured document with clear sections for each deliverable. Use diagrams where helpful. Focus on UNDERSTANDING, not implementation.

Remember: The goal is complete behavioral understanding. If you don't understand something, state that explicitly rather than guessing.
```

## Phase 1.2: Data Flow Analysis Prompt  

```
CRITICAL: Do NOT write any Rust code. This is pure data flow analysis.

Analyze the data flow patterns in C function `[FUNCTION_NAME]` in `[FILE_PATH]`.

### Required Deliverables:

1. **Input Analysis**
   - List all function parameters and their types
   - Identify expected ranges/constraints for each parameter
   - Document what happens with NULL/invalid inputs
   - Find all implicit inputs (global variables, static state)
   - Trace how each input affects function behavior

2. **Buffer Manipulation Sequences**
   - Map all buffer reads and writes
   - Document pointer arithmetic operations step-by-step
   - Identify buffer bounds checking (or lack thereof)
   - Show how buffer positions change throughout execution
   - Note any buffer overruns or underruns possible

3. **State Variable Modifications**
   - Track all local variable changes
   - Document global/static variable modifications
   - Show how state evolves through the function
   - Identify which variables are input, output, or internal
   - Map dependencies between state variables

4. **Output Generation Logic**
   - How are return values computed?
   - What determines each possible return value?
   - How are output parameters populated?
   - What side effects occur (file writes, global state changes)?

5. **Error Propagation Paths**
   - How are errors detected?
   - How are errors reported (return codes, errno, etc.)?
   - What cleanup occurs on error paths?
   - Are there any resource leaks on error?

### Analysis Approach:
- Start with function signature and parameter analysis
- Trace data flow from inputs to outputs
- Follow every variable assignment and modification
- Pay attention to aliasing (multiple pointers to same data)
- Document any assumptions about data layout or alignment

### Output Format:
Create a data flow diagram showing:
- Input sources → Processing steps → Output destinations
- All intermediate transformations
- Error propagation paths
- State changes over time

Use tables to document variable lifetimes and modification patterns.
```

## Phase 1.3: Invariant Discovery Prompt

```
CRITICAL: Do NOT write any Rust code. Focus solely on mathematical and logical properties.

Discover and document all invariants, preconditions, and postconditions for C function `[FUNCTION_NAME]` in `[FILE_PATH]`.

### Required Deliverables:

1. **Mathematical Relationships**
   - What numerical relationships must always hold? (e.g., `pos <= len`)
   - Which variables have bounds that must be maintained?
   - Are there any arithmetic operations that could overflow?
   - What happens at numerical boundaries (0, MAX_INT, etc.)?

2. **Preconditions**
   - What must be true when the function is called?
   - What parameter constraints exist?
   - What global state assumptions are made?
   - What happens if preconditions are violated?

3. **Postconditions**  
   - What is guaranteed to be true when function returns?
   - What relationships between inputs and outputs exist?
   - What global state changes are guaranteed?
   - How do postconditions differ for different return paths?

4. **Loop Invariants**
   - For each loop, what stays constant throughout iterations?
   - What properties hold at loop entry and exit?
   - How do loop variables relate to each other?
   - What guarantees loop termination?

5. **Memory Safety Properties**
   - Which pointers are guaranteed to be valid?
   - What buffer bounds are maintained?
   - Are there any use-after-free possibilities?
   - What about double-free or memory leaks?

6. **Implicit Contracts**
   - What does this function assume about its callers?
   - What does it guarantee to its callers?
   - How does it interact with other functions?
   - What global state contracts exist?

### Analysis Method:
1. Read the function completely first
2. Identify all assertions or checks (explicit and implicit)  
3. Look for patterns that suggest mathematical relationships
4. Examine error conditions - they often reveal expected invariants
5. Study how the function is called elsewhere to understand contracts

### Edge Case Systematic Analysis:
- Empty inputs (length 0, NULL pointers)
- Maximum size inputs  
- Boundary values (0, 1, MAX-1, MAX)
- Invalid UTF-8 or malformed data
- Resource exhaustion scenarios

### Output Format:
Document each invariant with:
- Mathematical expression (when applicable)
- Natural language description
- Where in the code it's established/maintained
- What happens if violated
- Whether it's checked or assumed

Group by: Function-level invariants, Loop-level invariants, Global invariants.

Remember: Invariants are properties that are ALWAYS true, not just usually true.
```

## Usage Instructions

1. **Sequential Application**: Use these prompts in order 1.1 → 1.2 → 1.3
2. **Complete Analysis First**: Don't proceed to Phase 2 until all three analyses are complete
3. **Documentation**: Save each analysis result in `docs/analysis/[FUNCTION_NAME]/`
4. **Verification**: Cross-reference results between phases to ensure consistency
5. **No Implementation**: Resist the urge to write Rust code until analysis is complete

## Expected Outputs

After all three phases, you should have:
- Complete understanding of function behavior
- All edge cases identified
- All mathematical properties documented  
- Clear contracts and assumptions
- Ready for faithful Rust translation

The analysis quality directly determines translation accuracy.