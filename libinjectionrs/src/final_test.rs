#[cfg(test)]
mod tests {
    use crate::detect_xss;

    #[test]
    fn test_final_xss_api() {
        let result = detect_xss(b"<script>alert(1)</script>");
        assert!(result.is_injection());
        println!("XSS Detection Result: {:?}", result);

        let safe_result = detect_xss(b"Hello world");
        assert!(!safe_result.is_injection());
        println!("Safe Result: {:?}", safe_result);
    }

    #[test]  
    fn test_crash_input() {
        use crate::xss::{Html5State, Html5Flags, TokenType, XssDetector, AttributeType};
        
        // Input bytes: [13, 60, 33, 255, 62, 60, 96, 60]
        // This is: \r<!�><`<
        let input = &[13u8, 60, 33, 255, 62, 60, 96, 60];
        
        println!("Testing crash input: {:?}", input);
        println!("As string (lossy): {:?}", String::from_utf8_lossy(input));
        
        // Test with detailed XSS trace
        let is_xss = debug_is_xss_with_trace(input, Html5Flags::DataState);
        println!("Debug function result: {}", is_xss);
        
        // Test with real detect_xss function
        let real_result = detect_xss(input);
        println!("Real detect_xss result: {:?} (is_injection: {})", real_result, real_result.is_injection());
        
        // Test each context individually to find the culprit
        println!("\n=== Testing each context individually ===");
        let contexts = [
            ("DataState", Html5Flags::DataState),
            ("ValueNoQuote", Html5Flags::ValueNoQuote),  
            ("ValueSingleQuote", Html5Flags::ValueSingleQuote),
            ("ValueDoubleQuote", Html5Flags::ValueDoubleQuote),
            ("ValueBackQuote", Html5Flags::ValueBackQuote),
        ];
        
        for (name, context) in &contexts {
            let is_xss_in_context = XssDetector::is_xss(input, *context);
            println!("{}: {}", name, is_xss_in_context);
            
            if is_xss_in_context {
                println!("  *** {} triggers false positive ***", name);
            }
        }
    }

    fn debug_is_xss_with_trace(input: &[u8], flags: crate::xss::Html5Flags) -> bool {
        use crate::xss::{Html5State, TokenType, XssDetector, AttributeType};
        
        println!("=== DETAILED XSS TRACE FOR DATA_STATE ===");
        let mut html5 = Html5State::new(input, flags);
        let mut attr = AttributeType::None;
        let mut token_count = 0;

        while html5.next() && token_count < 20 {
            token_count += 1;
            println!("Token {}: {:?}", token_count, html5.token_type);
            
            // Show token content for debugging
            if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                let token_slice = &html5.token_start[..html5.token_len];
                println!("  Content: {:?} (raw: {:?})", String::from_utf8_lossy(token_slice), token_slice);
            }
            
            // Reset attribute context if not ATTR_VALUE  
            if html5.token_type != TokenType::AttrValue {
                attr = AttributeType::None;
            }

            match html5.token_type {
                TokenType::Doctype => {
                    println!("  -> DOCTYPE detected - returning XSS=true");
                    return true;
                }
                TokenType::TagNameOpen => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let tag_slice = &html5.token_start[..html5.token_len];
                        println!("  -> Checking tag name: {:?}", String::from_utf8_lossy(tag_slice));
                        
                        // Use a public method or reimplement the logic
                        let is_blacklisted = tag_slice.len() >= 3 && {
                            // Check explicit blacklist
                            let blacklist = [
                                "APPLET", "BASE", "COMMENT", "EMBED", "FRAME", "FRAMESET", 
                                "HANDLER", "IFRAME", "IMPORT", "ISINDEX", "LINK", "LISTENER",
                                "META", "NOSCRIPT", "OBJECT", "SCRIPT", "STYLE", "VMLFRAME", "XML", "XSS"
                            ];
                            
                            let tag_upper = tag_slice.to_ascii_uppercase();
                            let tag_str = String::from_utf8_lossy(&tag_upper);
                            
                            blacklist.iter().any(|&black_tag| tag_str == black_tag) ||
                            tag_slice.len() >= 3 && (
                                tag_slice[..3].eq_ignore_ascii_case(b"svg") ||
                                tag_slice[..3].eq_ignore_ascii_case(b"xsl")
                            )
                        };
                        
                        if is_blacklisted {
                            println!("  -> Blacklisted tag detected - returning XSS=true");
                            return true;
                        }
                        println!("  -> Tag is safe");
                    }
                }
                TokenType::AttrName => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let attr_slice = &html5.token_start[..html5.token_len];
                        println!("  -> Checking attribute: {:?}", String::from_utf8_lossy(attr_slice));
                        // For simplicity, just set to None for now
                        attr = AttributeType::None;
                        println!("  -> Attribute type: None (simplified)");
                    }
                }
                TokenType::AttrValue => {
                    println!("  -> Processing attribute value with attr={:?}", attr);
                    match attr {
                        AttributeType::None => {
                            println!("  -> Safe attribute value");
                        }
                        AttributeType::Black => {
                            println!("  -> Blacklisted attribute value - returning XSS=true");
                            return true;
                        }
                        AttributeType::Style => {
                            println!("  -> Style attribute - returning XSS=true");
                            return true;
                        }
                        _ => {
                            println!("  -> Other attribute processing");
                        }
                    }
                    attr = AttributeType::None;
                }
                TokenType::TagComment => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let comment_slice = &html5.token_start[..html5.token_len];
                        println!("  -> Checking comment: {:?}", String::from_utf8_lossy(comment_slice));
                        
                        // Check for backtick
                        if comment_slice.contains(&b'`') {
                            println!("  -> Backtick in comment - returning XSS=true");
                            return true;
                        }
                        
                        // Check other dangerous patterns
                        let is_dangerous = comment_slice.len() > 3 && (
                            // IE conditional comment: [if 
                            (comment_slice.len() >= 3
                                && comment_slice[0] == b'['
                                && (comment_slice[1] == b'i' || comment_slice[1] == b'I')
                                && (comment_slice[2] == b'f' || comment_slice[2] == b'F')) ||
                            
                            // XML processing: xml
                            (comment_slice.len() >= 3
                                && (comment_slice[0] == b'x' || comment_slice[0] == b'X')
                                && (comment_slice[1] == b'm' || comment_slice[1] == b'M')
                                && (comment_slice[2] == b'l' || comment_slice[2] == b'L'))
                        ) || comment_slice.len() > 5 && (
                            // Check for IMPORT or ENTITY (case insensitive)
                            comment_slice.len() >= 6 && (
                                comment_slice[..6].eq_ignore_ascii_case(b"IMPORT") ||
                                comment_slice[..6].eq_ignore_ascii_case(b"ENTITY")
                            )
                        );
                        
                        if is_dangerous {
                            println!("  -> Dangerous comment detected - returning XSS=true");
                            return true;
                        }
                        println!("  -> Comment is safe");
                    }
                }
                _ => {
                    if html5.token_len > 0 && html5.token_len <= html5.token_start.len() {
                        let token_slice = &html5.token_start[..html5.token_len];
                        if token_slice.contains(&b'`') {
                            println!("  -> *** BACKTICK FOUND IN NON-COMMENT TOKEN! ***");
                            println!("  -> Token type: {:?}, Content: {:?}", html5.token_type, String::from_utf8_lossy(token_slice));
                            // This might be the bug - check if we have special handling for backticks outside comments
                        }
                    }
                    println!("  -> Other token type: {:?}", html5.token_type);
                }
            }
        }

        if token_count >= 20 {
            println!("  -> Stopped after 20 tokens (possible infinite loop)");
        }
        
        println!("  -> End of input reached - returning XSS=false");
        false
    }
}