# Phase 1.1: Algorithmic Understanding - libinjection_xss

## Function Purpose
`libinjection_xss()` and `libinjection_is_xss()` implement XSS (Cross-Site Scripting) detection by parsing HTML-like input and identifying potentially dangerous constructs that could enable script injection attacks.

## High-Level Behavioral Flowchart

```
libinjection_xss(s, slen) Entry Point
    │
    ├─► libinjection_is_xss(s, slen, DATA_STATE) ──► [1=XSS] ──► return 1
    │                                             └─► [0=safe] ──┐
    │                                                            │
    ├─► libinjection_is_xss(s, slen, VALUE_NO_QUOTE) ──► [1=XSS] ──► return 1
    │                                                 └─► [0=safe] ──┐
    │                                                                │
    ├─► libinjection_is_xss(s, slen, VALUE_SINGLE_QUOTE) ──► [1=XSS] ──► return 1
    │                                                     └─► [0=safe] ──┐
    │                                                                    │
    ├─► libinjection_is_xss(s, slen, VALUE_DOUBLE_QUOTE) ──► [1=XSS] ──► return 1
    │                                                     └─► [0=safe] ──┐
    │                                                                    │
    ├─► libinjection_is_xss(s, slen, VALUE_BACK_QUOTE) ──► [1=XSS] ──► return 1
    │                                                   └─► [0=safe] ──┐
    │                                                                  │
    └─► All contexts safe ◄─────────────────────────────────────────────┘
        │
        └─► return 0 (no XSS detected)
```

## Core Detection Algorithm (libinjection_is_xss)

```
libinjection_is_xss(s, len, flags)
    │
    ├─► Initialize HTML5 parser state (h5_state_t)
    │   └─► Set parsing context based on flags
    │
    └─► Token Processing Loop:
        │
        ├─► libinjection_h5_next(&h5) ──► [false] ──► return 0 (end of input, safe)
        │                              └─► [true] ──► Continue processing
        │
        ├─► Reset attribute context if not ATTR_VALUE
        │   └─► attr = TYPE_NONE
        │
        └─► Switch on token_type:
            │
            ├─► DOCTYPE ──► return 1 (XSS: DOCTYPE declarations dangerous)
            │
            ├─► TAG_NAME_OPEN ──► is_black_tag() ──► [true] ──► return 1
            │                                     └─► [false] ──► continue
            │
            ├─► ATTR_NAME ──► is_black_attr() ──► attr = result_type
            │
            ├─► ATTR_VALUE ──► Switch on attr:
            │   │
            │   ├─► TYPE_NONE ──► continue (safe attribute)
            │   ├─► TYPE_BLACK ──► return 1 (dangerous attribute)
            │   ├─► TYPE_ATTR_URL ──► is_black_url() ──► [true] ──► return 1
            │   │                                     └─► [false] ──► continue
            │   ├─► TYPE_STYLE ──► return 1 (CSS injection risk)
            │   └─► TYPE_ATTR_INDIRECT ──► is_black_attr() ──► [true] ──► return 1
            │                                               └─► [false] ──► continue
            │
            └─► TAG_COMMENT ──► Multiple checks:
                │
                ├─► Contains '`' ──► return 1 (IE parsing quirk)
                │
                ├─► Starts with "[if" ──► return 1 (IE conditional comment)
                │
                ├─► Starts with "xml" ──► return 1 (XML processing)
                │
                ├─► Contains "IMPORT" ──► return 1 (IE import pseudo-tag)
                │
                └─► Contains "ENTITY" ──► return 1 (XML entity definition)
```

## State Machine Analysis

### HTML5 Parser State Machine
The algorithm relies on the HTML5 parser (`libinjection_h5_*`) which implements a state machine to tokenize HTML input. The state machine handles different parsing contexts:

1. **DATA_STATE**: Normal HTML content
2. **VALUE_NO_QUOTE**: Attribute values without quotes
3. **VALUE_SINGLE_QUOTE**: Attribute values in single quotes
4. **VALUE_DOUBLE_QUOTE**: Attribute values in double quotes  
5. **VALUE_BACK_QUOTE**: Attribute values in backticks (non-standard)

### Attribute Type State Machine
```
ATTR_NAME token encountered
    │
    ├─► is_black_attr(name) ──► Returns attribute_t:
        │
        ├─► TYPE_NONE ──► Safe attribute, no special handling
        ├─► TYPE_BLACK ──► Always dangerous (event handlers, etc.)
        ├─► TYPE_ATTR_URL ──► URL attribute, check value for dangerous protocols
        ├─► TYPE_STYLE ──► Style attribute, always dangerous (CSS injection)
        └─► TYPE_ATTR_INDIRECT ──► Attribute name specified in value (SVG)

ATTR_VALUE token encountered
    │
    └─► Use stored attribute_t to determine value validation
```

## Execution Path Enumeration

### Path 1: Immediate XSS Detection
- **Trigger**: DOCTYPE token found
- **Action**: Return 1 immediately
- **Rationale**: DOCTYPE can enable quirks mode parsing vulnerabilities

### Path 2: Dangerous Tag Detection  
- **Trigger**: TAG_NAME_OPEN with blacklisted tag name
- **Examples**: `<script>`, `<iframe>`, `<object>`, `<embed>`, etc.
- **Action**: Return 1 immediately

### Path 3: Event Handler Detection
- **Trigger**: ATTR_NAME starting with "on" + known event name
- **Examples**: `onclick`, `onload`, `onerror`, etc.
- **Action**: Mark attribute as TYPE_BLACK, return 1 on next ATTR_VALUE

### Path 4: URL Protocol Injection
- **Trigger**: ATTR_VALUE for URL attribute (href, src, action, etc.)
- **Dangerous protocols**: `javascript:`, `data:`, `vbscript:`, `view-source:`
- **Action**: Return 1 if dangerous protocol detected

### Path 5: CSS Injection
- **Trigger**: ATTR_VALUE for style attribute
- **Action**: Return 1 immediately (CSS can contain script-like constructs)

### Path 6: Comment-Based Attacks
- **Trigger**: TAG_COMMENT with various dangerous patterns
- **Examples**: IE conditional comments, XML processing instructions
- **Action**: Return 1 if patterns match

### Path 7: Safe Input
- **Trigger**: End of input reached without finding dangerous patterns
- **Action**: Return 0

## Multiple Context Testing Strategy

The wrapper `libinjection_xss()` tests input in 5 different HTML parsing contexts to catch context-specific attacks:

1. **DATA_STATE**: Normal HTML content context
2. **VALUE_NO_QUOTE**: Unquoted attribute value context  
3. **VALUE_SINGLE_QUOTE**: Single-quoted attribute value context
4. **VALUE_DOUBLE_QUOTE**: Double-quoted attribute value context
5. **VALUE_BACK_QUOTE**: Backtick-quoted attribute value context (IE quirk)

This multi-context approach ensures that malicious input cannot escape detection by exploiting parsing differences between contexts.