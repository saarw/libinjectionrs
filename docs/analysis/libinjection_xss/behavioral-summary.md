# Behavioral Summary - libinjection_xss

## Overview
The libinjection XSS detection system implements a multi-context HTML parser that identifies potentially dangerous XSS patterns in user input. The implementation consists of two main functions working together with an HTML5 tokenizer to provide comprehensive cross-site scripting detection.

## Core Architecture

### Primary Functions
- **`libinjection_xss(s, slen)`**: Main entry point that tests input across 5 different HTML parsing contexts
- **`libinjection_is_xss(s, len, flags)`**: Core detection logic for a specific HTML parsing context  
- **Supporting functions**: HTML entity decoding, blacklist matching, case-insensitive string comparison

### Multi-Context Strategy
The system tests each input string in 5 different HTML parsing contexts to catch context-specific attack vectors:
1. `DATA_STATE` - Normal HTML content
2. `VALUE_NO_QUOTE` - Unquoted attribute values  
3. `VALUE_SINGLE_QUOTE` - Single-quoted attribute values
4. `VALUE_DOUBLE_QUOTE` - Double-quoted attribute values
5. `VALUE_BACK_QUOTE` - Backtick-quoted attribute values (IE-specific)

## Detection Mechanisms

### Blacklist-Based Detection
The system maintains several blacklists for dangerous constructs:

**Dangerous HTML Tags**: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<style>`, etc., plus any SVG (`svg*`) or XSL (`xsl*`) tags

**Event Handler Attributes**: 400+ event handler names from WebKit (`onclick`, `onload`, `onerror`, etc.)

**URL Attributes**: `href`, `src`, `action`, etc. checked for dangerous protocols

**Dangerous URL Protocols**: `javascript:`, `data:`, `vbscript:`, `view-source:`

### HTML5 Tokenization
Uses a standards-compliant HTML5 tokenizer to parse input and extract:
- Tag names (opening/closing/self-closing)
- Attribute names and values  
- Comments
- DOCTYPE declarations
- Text content

### Immediate Threat Detection
Several patterns trigger immediate XSS detection:
- **DOCTYPE declarations** (can enable parsing quirks)
- **Blacklisted HTML tags**  
- **Event handler attributes**
- **Style attributes** (CSS injection risk)
- **Dangerous URL protocols**
- **IE-specific comment exploits** (conditional comments, backticks)
- **XML processing constructs** (entities, imports)

## Key Behavioral Properties

### Input Handling
- **Binary safe**: Handles arbitrary byte sequences including null bytes
- **Length-aware**: Uses explicit length parameters, not null termination  
- **Non-destructive**: Never modifies input data
- **Fault-tolerant**: Gracefully handles malformed HTML

### HTML Entity Decoding
- **Standards-compliant**: Supports `&#decimal;` and `&#xhex;` entities
- **Partial parsing**: Returns partial results for incomplete entities
- **Overflow protection**: Limits entity values to prevent overflow
- **Null-byte resilience**: Ignores embedded nulls during decoding

### Case Handling
- **Case-insensitive matching**: All HTML tag/attribute comparisons ignore case
- **Uppercase normalization**: Converts input to uppercase for comparison
- **Null-byte skipping**: Ignores embedded nulls in input during comparison

### Performance Characteristics  
- **Linear time complexity**: O(input_length × context_count)
- **Constant memory**: Uses only stack-allocated data structures
- **Short-circuit evaluation**: Returns immediately on first XSS detection
- **No memory allocation**: Works entirely with input buffer pointers

## Security Properties

### Coverage Strategy
- **Multiple parsing contexts** catch context-specific escaping vulnerabilities
- **Comprehensive blacklists** cover known dangerous HTML constructs  
- **Protocol validation** prevents URL-based script injection
- **Comment analysis** catches IE-specific parsing quirks

### Limitations
- **Heuristic approach**: May miss novel attack vectors not in blacklists
- **No semantic analysis**: Cannot detect logic-based vulnerabilities  
- **Context assumptions**: Limited to HTML context, not other formats
- **Encoding blind spots**: May miss attacks using unusual character encodings

## Implementation Invariants

### Memory Safety
- All buffer access is bounds-checked through length parameters
- No dynamic memory allocation eliminates memory leaks/corruption
- Token pointers always reference valid input buffer locations
- Stack-only data structures prevent heap-based vulnerabilities

### Determinism
- Pure function with no global state dependencies
- Identical input always produces identical output  
- No randomization or timing-dependent behavior
- Thread-safe (no shared mutable state)

### Robustness
- Handles NULL input pointers gracefully
- Zero-length input is processed correctly
- Malformed HTML does not cause crashes or errors
- Parser state is completely local to each function call

## Critical Edge Cases

### HTML Entity Handling
- Incomplete entities: `&#123` returns partial value 123
- Invalid hex: `&#xGHI` stops at first invalid character  
- Overflow values: `&#999999999999` returns '&' literal
- Mixed case: `&#xAbC` handles both upper and lower case hex

### IE-Specific Quirks
- Backtick comment termination: `<!-- content ` ` -->` 
- Conditional comments: `<!--[if IE]>`
- Import pseudo-tags: `<!--IMPORT ...-->`

### Multi-Byte Considerations
- High-bit characters treated as potential UTF-8 whitespace
- EUC-JP high bytes may be ignored in some contexts
- Signed character handling for values > 127

This behavioral analysis provides the foundation for creating a functionally equivalent Rust implementation that maintains all security properties and edge case handling of the original C code.