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
            // Reset attribute context if not ATTR_VALUE  
            if html5.token_type != TokenType::AttrValue {
                attr = AttributeType::None;
            }

            match html5.token_type {
                TokenType::Doctype => {
                    return true; // DOCTYPE declarations are dangerous
                }
                TokenType::TagNameOpen => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let tag_content = &html5.token_start[..html5.token_len];
                        if Self::is_black_tag(tag_content) {
                            return true;
                        }
                    }
                }
                TokenType::AttrName => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let attr_content = &html5.token_start[..html5.token_len];
                        attr = Self::is_black_attr(attr_content);
                    }
                }
                TokenType::AttrValue => {
                    match attr {
                        AttributeType::None => {
                            // Safe attribute, continue
                        }
                        AttributeType::Black => {
                            return true; // Always dangerous
                        }
                        AttributeType::AttrUrl => {
                            if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                                let url_content = &html5.token_start[..html5.token_len];
                                if Self::is_black_url(url_content) {
                                    return true;
                                }
                            }
                        }
                        AttributeType::Style => {
                            return true; // CSS injection risk
                        }
                        AttributeType::AttrIndirect => {
                            // Attribute name specified in value (SVG)
                            if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                                let indirect_content = &html5.token_start[..html5.token_len];
                                if Self::is_black_attr(indirect_content) != AttributeType::None {
                                    return true;
                                }
                            }
                        }
                    }
                    attr = AttributeType::None;
                }
                TokenType::TagComment => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let comment_content = &html5.token_start[..html5.token_len];
                        if Self::is_dangerous_comment(comment_content) {
                            return true;
                        }
                    }
                }
                _ => {
                    // Other token types are generally safe
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

        // Check SVG tags (case insensitive)
        if tag_name.len() >= 3 {
            let first_three = &tag_name[..3];
            if first_three.eq_ignore_ascii_case(b"svg") {
                return true;
            }
        }

        // Check XSL tags (case insensitive)
        if tag_name.len() >= 3 {
            let first_three = &tag_name[..3];
            if first_three.eq_ignore_ascii_case(b"xsl") {
                return true;
            }
        }

        false
    }

    fn is_black_attr(attr_name: &[u8]) -> AttributeType {
        if attr_name.len() < 2 {
            return AttributeType::None;
        }

        // Check for event handlers (on* attributes)
        if attr_name.len() >= 5 {
            let first_two = &attr_name[..2];
            if first_two.eq_ignore_ascii_case(b"on") {
                let event_name = &attr_name[2..];
                for event in BLACK_ATTR_EVENTS {
                    if Self::cstrcasecmp_with_null(event.name.as_bytes(), event_name) {
                        return event.atype;
                    }
                }
            }

            // Check XMLNS and XLINK
            if Self::cstrcasecmp_with_null(b"XMLNS", attr_name) 
                || Self::cstrcasecmp_with_null(b"XLINK", attr_name) {
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

    // Case-insensitive string comparison that ignores null bytes
    fn cstrcasecmp_with_null(pattern: &[u8], input: &[u8]) -> bool {
        let mut pattern_idx = 0;
        let mut input_idx = 0;

        while pattern_idx < pattern.len() && input_idx < input.len() {
            if input[input_idx] == 0 {
                input_idx += 1;
                continue;
            }

            let pattern_char = pattern[pattern_idx];
            let mut input_char = input[input_idx];

            // Convert to uppercase
            if input_char >= b'a' && input_char <= b'z' {
                input_char -= 0x20;
            }

            if pattern_char != input_char {
                return false;
            }

            pattern_idx += 1;
            input_idx += 1;
        }

        // Pattern must be fully consumed
        pattern_idx == pattern.len()
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