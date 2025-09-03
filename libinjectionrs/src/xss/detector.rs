use super::blacklists::{
    AttributeType, BLACK_ATTR_EVENTS, BLACK_ATTRS, BLACK_TAGS, BLACK_URL_PROTOCOLS,
    html_decode_char_at,
};
use super::html5::{Html5Flags, Html5State, TokenType};

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XssResult {
    Safe,
    Xss,
}

impl XssResult {
    pub fn is_injection(&self) -> bool {
        matches!(self, XssResult::Xss)
    }
}

impl fmt::Display for XssResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XssResult::Safe => write!(f, "Safe"),
            XssResult::Xss => write!(f, "XSS"),
        }
    }
}

pub struct XssDetector {
    // Currently stateless, but kept for future expansion
}

impl XssDetector {
    pub fn new() -> Self {
        Self {}
    }

    pub fn detect(&self, input: &[u8]) -> XssResult {
        // Test input across all 5 HTML parsing contexts
        let contexts = [
            Html5Flags::DataState,
            Html5Flags::ValueNoQuote,
            Html5Flags::ValueSingleQuote,
            Html5Flags::ValueDoubleQuote,
            Html5Flags::ValueBackQuote,
        ];

        for &context in &contexts {
            if Self::is_xss(input, context) {
                return XssResult::Xss;
            }
        }

        XssResult::Safe
    }

    pub fn is_xss(input: &[u8], flags: Html5Flags) -> bool {
        let mut html5 = Html5State::new(input, flags);
        let mut attr = AttributeType::None;

        while html5.next() {
            if html5.token_type != TokenType::AttrValue {
                attr = AttributeType::None;
            }

            if html5.token_type == TokenType::Doctype {
                return true;
            } else if html5.token_type == TokenType::TagNameOpen {
                if Self::is_black_tag(&html5.token_start[..html5.token_len]) {
                    return true;
                }
            } else if html5.token_type == TokenType::AttrName {
                attr = Self::is_black_attr(&html5.token_start[..html5.token_len]);
            } else if html5.token_type == TokenType::AttrValue {
                match attr {
                    AttributeType::None => {
                        // break equivalent 
                    }
                    AttributeType::Black => {
                        return true;
                    }
                    AttributeType::AttrUrl => {
                        if Self::is_black_url(&html5.token_start[..html5.token_len]) {
                            return true;
                        }
                    }
                    AttributeType::Style => {
                        return true;
                    }
                    AttributeType::AttrIndirect => {
                        // an attribute name is specified in a _value_
                        if Self::is_black_attr(&html5.token_start[..html5.token_len]) != AttributeType::None {
                            return true;
                        }
                    }
                }
                attr = AttributeType::None;
            } else if html5.token_type == TokenType::TagComment {
                // IE uses a "`" as a tag ending char
                if html5.token_start[..html5.token_len].contains(&b'`') {
                    return true;
                }

                // IE conditional comment
                if html5.token_len > 3 {
                    if html5.token_start[0] == b'[' &&
                        (html5.token_start[1] == b'i' || html5.token_start[1] == b'I') &&
                        (html5.token_start[2] == b'f' || html5.token_start[2] == b'F') {
                        return true;
                    }
                    if (html5.token_start[0] == b'x' || html5.token_start[0] == b'X') &&
                        (html5.token_start[1] == b'm' || html5.token_start[1] == b'M') &&
                        (html5.token_start[2] == b'l' || html5.token_start[2] == b'L') {
                        return true;
                    }
                }

                if html5.token_len > 5 {
                    // IE <?import pseudo-tag
                    if Self::cstrcasecmp_with_null(b"IMPORT", &html5.token_start[..6]) {
                        return true;
                    }

                    // XML Entity definition
                    if Self::cstrcasecmp_with_null(b"ENTITY", &html5.token_start[..6]) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn is_black_tag(tag_name: &[u8]) -> bool {
        if tag_name.len() < 3 {
            return false;
        }

        // Check explicit blacklist
        for &black_tag in BLACK_TAGS {
            if Self::cstrcasecmp_with_null(black_tag.as_bytes(), tag_name) {
                return true;
            }
        }

        // Check SVG tags (case insensitive) - match C's manual case checking exactly
        if tag_name.len() >= 3 {
            if (tag_name[0] == b's' || tag_name[0] == b'S') &&
               (tag_name[1] == b'v' || tag_name[1] == b'V') &&
               (tag_name[2] == b'g' || tag_name[2] == b'G') {
                return true;
            }
        }

        // Check XSL tags (case insensitive) - match C's manual case checking exactly
        if tag_name.len() >= 3 {
            if (tag_name[0] == b'x' || tag_name[0] == b'X') &&
               (tag_name[1] == b's' || tag_name[1] == b'S') &&
               (tag_name[2] == b'l' || tag_name[2] == b'L') {
                return true;
            }
        }

        false
    }

    fn is_black_attr(attr_name: &[u8]) -> AttributeType {
        if attr_name.len() < 2 {
            return AttributeType::None;
        }

        // Check for event handlers (on* attributes) - match C's manual case checking exactly
        if attr_name.len() >= 5 {
            if (attr_name[0] == b'o' || attr_name[0] == b'O') &&
               (attr_name[1] == b'n' || attr_name[1] == b'N') {
                let event_name = &attr_name[2..];
                for event in BLACK_ATTR_EVENTS {
                    if Self::cstrcasecmp_with_null(event.name.as_bytes(), event_name) {
                        return event.atype;
                    }
                }
            }

            // Check XMLNS and XLINK - use prefix matching like C (checks first 5 chars only)
            if Self::cstrcasecmp_with_null_limited(b"XMLNS", attr_name, 5) 
                || Self::cstrcasecmp_with_null_limited(b"XLINK", attr_name, 5) {
                return AttributeType::Black;
            }
        }

        // Check other blacklisted attributes
        for attr in BLACK_ATTRS {
            if Self::cstrcasecmp_with_null(attr.name.as_bytes(), attr_name) {
                return attr.atype;
            }
        }

        AttributeType::None
    }

    fn is_black_url(url: &[u8]) -> bool {
        if url.is_empty() {
            return false;
        }

        // Skip leading whitespace and high-bit characters
        let mut start = 0;
        while start < url.len() {
            let ch = url[start];
            if ch <= 32 || ch >= 127 {
                start += 1;
            } else {
                break;
            }
        }

        if start >= url.len() {
            return false;
        }

        let url_trimmed = &url[start..];

        // Check dangerous protocols
        for &protocol in BLACK_URL_PROTOCOLS {
            if Self::htmlencode_startswith(protocol.as_bytes(), url_trimmed) {
                return true;
            }
        }

        false
    }

    #[allow(dead_code)] // Follows C implementation - may be used in future XSS detection features
    fn is_dangerous_comment(comment: &[u8]) -> bool {
        // IE uses backtick as tag ending character
        if comment.contains(&b'`') {
            return true;
        }

        if comment.len() > 3 {
            // IE conditional comment: [if 
            if comment.len() >= 3
                && comment[0] == b'['
                && (comment[1] == b'i' || comment[1] == b'I')
                && (comment[2] == b'f' || comment[2] == b'F')
            {
                return true;
            }

            // XML processing: xml
            if comment.len() >= 3
                && (comment[0] == b'x' || comment[0] == b'X')
                && (comment[1] == b'm' || comment[1] == b'M')
                && (comment[2] == b'l' || comment[2] == b'L')
            {
                return true;
            }
        }

        if comment.len() > 5 {
            // IE import pseudo-tag
            if Self::cstrcasecmp_with_null(b"IMPORT", &comment[..6]) {
                return true;
            }

            // XML entity definition
            if Self::cstrcasecmp_with_null(b"ENTITY", &comment[..6]) {
                return true;
            }
        }

        false
    }

    // Case-insensitive string comparison that ignores null bytes - prefix version
    // Replicates C's cstrcasecmp_with_null(pattern, input, n) where n limits input length
    fn cstrcasecmp_with_null_limited(pattern: &[u8], input: &[u8], n: usize) -> bool {
        let mut pattern_idx = 0;
        let mut input_idx = 0;
        let mut remaining = n;
        
        while remaining > 0 && input_idx < input.len() {
            let input_char = input[input_idx];
            input_idx += 1;
            remaining -= 1;
            
            // Skip null bytes in input (like C's cb == '\0')
            if input_char == 0 {
                continue;
            }
            
            // Always advance pattern pointer (like C's ca = a[ai++])
            if pattern_idx >= pattern.len() {
                return false; // Pattern exhausted but input continues within n chars
            }
            let pattern_char = pattern[pattern_idx];
            pattern_idx += 1;
            
            // Convert input character to uppercase (like C)
            let mut cb = input_char;
            if cb >= b'a' && cb <= b'z' {
                cb -= 0x20;
            }
            
            // Compare characters (like C's ca != cb)
            if pattern_char != cb {
                return false;
            }
        }
        
        // Check if pattern is fully consumed (like C's final ca = a[ai++]; ca == '\0')
        pattern_idx >= pattern.len()
    }

    // Case-insensitive string comparison that ignores null bytes
    // Replicates the exact behavior of C's cstrcasecmp_with_null function
    fn cstrcasecmp_with_null(pattern: &[u8], input: &[u8]) -> bool {
        let mut pattern_idx = 0;
        let mut input_idx = 0;
        
        // Loop through input length (like C's n-- > 0)
        while input_idx < input.len() {
            let input_char = input[input_idx];
            input_idx += 1;
            
            // Skip null bytes in input (like C's cb == '\0')
            if input_char == 0 {
                continue;
            }
            
            // Always advance pattern pointer (like C's ca = a[ai++])
            if pattern_idx >= pattern.len() {
                return false; // Pattern exhausted but input continues
            }
            let pattern_char = pattern[pattern_idx];
            pattern_idx += 1;
            
            // Convert input character to uppercase (like C)
            let mut cb = input_char;
            if cb >= b'a' && cb <= b'z' {
                cb -= 0x20;
            }
            
            // Compare characters (like C's ca != cb)
            if pattern_char != cb {
                return false;
            }
        }
        
        // Check if pattern is fully consumed (like C's final ca = a[ai++]; ca == '\0')
        // In C, this reads the next character and checks if it's null terminator
        if pattern_idx >= pattern.len() {
            return true; // Pattern fully consumed (equivalent to C's ca == '\0')
        } else {
            return false; // Pattern not fully consumed (equivalent to C's ca != '\0')
        }
    }

    // HTML-encoded string starts with pattern (case insensitive)
    fn htmlencode_startswith(pattern: &[u8], input: &[u8]) -> bool {
        let mut pattern_idx = 0;
        let mut input_pos = 0;
        let mut first = true;

        while input_pos < input.len() && pattern_idx < pattern.len() {
            let mut consumed = 0;
            let decoded_char = html_decode_char_at(&input[input_pos..], &mut consumed);
            
            input_pos += consumed;

            // Skip leading whitespace and control characters
            if first && decoded_char <= 32 {
                continue;
            }
            first = false;

            // Always ignore null characters
            if decoded_char == 0 {
                continue;
            }

            // Always ignore vertical tab characters  
            if decoded_char == 10 {
                continue;
            }

            // Convert to uppercase
            let mut char_to_compare = decoded_char;
            if char_to_compare >= (b'a' as i32) && char_to_compare <= (b'z' as i32) {
                char_to_compare -= 0x20;
            }

            if pattern[pattern_idx] as i32 != char_to_compare {
                return false;
            }

            pattern_idx += 1;
        }

        pattern_idx == pattern.len()
    }
}

impl Default for XssDetector {
    fn default() -> Self {
        Self::new()
    }
}