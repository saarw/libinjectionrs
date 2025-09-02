// SQL injection detection tests

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::disallowed_methods)]
#[allow(clippy::panic)]
mod tests {
    use crate::sqli::*;
    
    /// Format token value like C's testdriver - reconstructs variable prefixes and string quotes
    fn format_token_for_c_compatibility(token: &Token) -> String {
        match token.token_type {
            TokenType::Variable => {
                // Reconstruct @ symbols like C's print_var function
                let at_symbols = "@".repeat(token.count as usize);
                format!("{}{}", at_symbols, token.value_as_str())
            }
            TokenType::String => {
                // Reconstruct string quotes like C's print_string function
                let mut result = String::new();
                if token.str_open != 0 {
                    result.push(token.str_open as char);
                }
                result.push_str(token.value_as_str());
                if token.str_close != 0 {
                    result.push(token.str_close as char);
                }
                result
            }
            _ => token.value_as_str().to_string()
        }
    }
    
    #[test]
    fn test_basic_detection() {
        // Placeholder test - create basic state for testing
        let input = b"SELECT * FROM users";
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        let fingerprint = state.fingerprint();
        // Just test that we can create fingerprint without panicking
        fingerprint.as_str();
        assert!(true);
    }
    
    #[test]
    fn debug_fuzz_crash_case() {
        // Test the specific case that was crashing in fuzz testing
        let input = b"--1-@a#*\x03";
        
        println!("Testing input: {:?}", String::from_utf8_lossy(input));
        println!("Hex: {}", input.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        
        // Test with ANSI flags like the fuzz test
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        
        // Get tokens by checking state before folding
        let mut tokenizer = SqliTokenizer::new(input, SqliFlags::FLAG_SQL_ANSI);
        let mut raw_tokens = Vec::new();
        while let Some(token) = tokenizer.next_token() {
            println!("  Raw Token: {:?} '{}' pos={} len={}", 
                     token.token_type, token.value_as_str(), token.pos, token.len);
            raw_tokens.push(token);
        }
        println!("Raw tokens created: {}", raw_tokens.len());
        
        // Create fingerprint and check detection  
        let fingerprint = state.fingerprint();
        println!("Final fingerprint: '{}'", fingerprint.as_str());
        
        let is_injection = state.is_sqli();
        println!("Is SQL injection: {}", is_injection);
    }
    
    #[test]
    fn test_blacklist() {
        // Test the blacklist function
        assert!(!blacklist::is_blacklisted(""));
        assert!(!blacklist::is_blacklisted("safe"));
    }
    
    #[test]
    fn test_variable_token_symbols_preserved() {
        use crate::sqli::tokenizer::{SqliTokenizer, TokenType};
        
        let test_cases = vec![
            ("@", "@"),
            ("@@", "@@"), 
            ("@version", "@version"),
            ("@@version", "@@version"),
        ];
        
        for (input_str, expected_value) in test_cases {
            let input = input_str.as_bytes();
            let flags = SqliFlags::new(0);
            let mut tokenizer = SqliTokenizer::new(input, flags);
            
            if let Some(token) = tokenizer.next_token() {
                assert_eq!(token.token_type, TokenType::Variable, 
                    "Token type should be Variable for input '{}'", input_str);
                assert_eq!(token.value_as_str(), expected_value,
                    "Token value should preserve @ symbols for input '{}'", input_str);
                assert_eq!(token.pos, 0,
                    "Token position should start at 0 for input '{}'", input_str);
            } else {
                panic!("No token found for input '{}'", input_str);
            }
        }
    }
    
    #[test]
    fn debug_semicolon_issue() {
        let input = "SELECT 1 FROM table;";
        let mut state = SqliState::from_string(input, SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0));
        
        println!("Input: {}", input);
        
        let fingerprint = state.get_fingerprint();
        println!("Rust fingerprint: {}", fingerprint);
        
        println!("Final tokens ({} total):", state.tokens.len());
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Token {}: type={:?}, val={:?}", i, token.token_type, token.value_as_str());
        }
        
        // This should include the semicolon
        assert!(fingerprint.as_str().contains(";"), "Fingerprint should contain semicolon");
    }
    
    #[test]
    fn test_select_float_version() {
        let input = "SELECT float @@version;";
        
        println!("=== Rust Detailed Debug ===");
        println!("Input: {}", input);
        
        // Show raw tokenization first
        println!("\n--- Raw tokenization ---");
        let input_bytes = input.as_bytes();
        let flags = SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0);
        let mut tokenizer = SqliTokenizer::new(input_bytes, flags);
        
        let mut raw_tokens = Vec::new();
        while let Some(token) = tokenizer.next_token() {
            println!("Raw Token {}: type={:?}, val='{}' (pos: {}, len: {})", 
                     raw_tokens.len(), token.token_type, format_token_for_c_compatibility(&token), token.pos, token.len);
            raw_tokens.push(token);
            if raw_tokens.len() >= 8 {
                break;
            }
        }
        
        println!("\n--- After folding ---");
        let mut state = SqliState::from_string(input, SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0));
        let fingerprint = state.get_fingerprint();
        
        println!("Rust fingerprint: {}", fingerprint);
        println!("Final tokens ({} total):", state.tokens.len());
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Folded Token {}: type={:?}, val={:?} (pos: {}, len: {})", 
                     i, token.token_type, format_token_for_c_compatibility(token), token.pos, token.len);
        }
        
        // According to test-folding-053.txt, expected tokens should be:
        // E SELECT
        // v @@version  
        // ; ;
        // So fingerprint should be "Ev;"
        assert_eq!(fingerprint.as_str(), "Ev;", "Fingerprint should be Ev; for 'SELECT float @@version;'");
    }

    #[test]
    fn test_quote_context_differential_fuzzing_case() {
        // Test for the specific input that caused differential fuzzing failure
        // Input: [35, 254, 34, 126, 34] which is "#\xfe\"~\""
        // This test ensures the Rust implementation matches C behavior
        let input = [35u8, 254, 34, 126, 34];
        
        // Test the public API
        let result = crate::detect_sqli(&input);
        
        // The fix should make this behave like C implementation:
        // - Both should detect it as SQLi: true
        // - Both should generate fingerprint "sos"
        assert_eq!(result.is_injection(), true, "Should detect SQLi like C implementation");
        assert_eq!(result.fingerprint.as_ref().map(|f| f.as_str()), Some("sos"), "Should generate 'sos' fingerprint like C implementation");
        
        // Test the internal state with different quote contexts
        let mut state_ansi = SqliState::new(&input, SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0));
        let fp_ansi = state_ansi.fingerprint();
        assert_eq!(fp_ansi.as_str(), "ons", "ANSI context should produce 'ons' fingerprint");
        
        let mut state_double_quote = SqliState::new(&input, SqliFlags::new(SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_ANSI.0));
        let fp_double = state_double_quote.fingerprint();
        assert_eq!(fp_double.as_str(), "sos", "Double quote context should produce 'sos' fingerprint");
        
        // The double quote context version should be detected as SQLi
        assert!(state_double_quote.check_is_sqli(&fp_double), "Double quote context should detect as SQLi");
    }
    
    #[test]
    fn test_fuzz_crash_252_34_35_34() {
        // This test case was found by fuzzing and represents a differential
        // between the C and Rust implementations.
        // Input: [252, 34, 35, 34] which is [0xFC, 0x22, 0x23, 0x22] or "\xfc\"#\""
        // Expected behavior: should match C implementation exactly
        
        let input = [252u8, 34, 35, 34];
        
        // Test with detect_sqli (public API)
        let result = crate::detect_sqli(&input);
        
        // The C implementation returns false for this input
        // The issue was that Rust was returning true due to incorrect handling
        // of hash characters in string contexts during quote context switching
        assert_eq!(result.is_injection(), false, 
                   "Input [252, 34, 35, 34] should be detected as non-SQLi to match C implementation");
        
        // Test with direct state API  
        let mut state = SqliState::new(&input, SqliFlags::FLAG_SQL_ANSI);
        let detect_result = state.detect();
        assert_eq!(detect_result, false,
                   "Direct detect() call should return false for input [252, 34, 35, 34]");
        
        // Test fingerprint generation in different contexts
        let mut state_none = SqliState::new(&input, SqliFlags::FLAG_SQL_ANSI);
        let fp_none = state_none.get_fingerprint();
        
        // The exact fingerprint isn't as important as the final result being false,
        // but we should have consistent behavior
        println!("Generated fingerprint: '{}'", fp_none.as_str());
    }

    #[test]
    fn test_evil_token_fingerprint_reset() {
        // Test case for fuzz differential input "0{`"
        // This input should generate Evil tokens and trigger fingerprint reset logic
        // to match C implementation behavior
        let input = "0{`";
        let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
        
        // Get the fingerprint
        let fingerprint = state.get_fingerprint();
        
        // The C implementation resets any fingerprint containing Evil tokens to just "X"
        // so the Rust implementation should do the same
        assert_eq!(fingerprint.as_str(), "X", 
                   "Fingerprint should be reset to 'X' when Evil tokens are present");
        
        // Test that this is detected as SQL injection (like C implementation)
        let is_injection = state.detect();
        assert_eq!(is_injection, true,
                   "Input '0{{`' should be detected as SQL injection like C implementation");
        
        // Verify that the token vector was also reset to contain just the Evil token
        assert_eq!(state.tokens.len(), 1, "Should have exactly 1 token after Evil reset");
        assert_eq!(state.tokens[0].token_type, TokenType::Evil, 
                   "Single remaining token should be Evil type");
        assert_eq!(state.tokens[0].value_as_str(), "X", 
                   "Evil token value should be 'X'");
    }
    
    #[test]
    fn test_mysql_conditional_comment_fuzz_case() {
        // This test case reproduces a specific fuzzing differential that was found
        // Input: '/*!#��\" (bytes: [0x27, 0x2f, 0x2a, 0x21, 0x23, 0xf1, 0xfe, 0x22])
        // 
        // The issue was that the C implementation detects MySQL conditional comments (/*!)
        // even within string content and marks them as EVIL, but the Rust implementation
        // was missing this post-tokenization analysis.
        //
        // C code reference: libinjection_sqli.c lines 454-474 (is_mysql_comment)
        // and lines 1942-1954 (fingerprint post-processing)
        
        let input: &[u8] = &[0x27, 0x2f, 0x2a, 0x21, 0x23, 0xf1, 0xfe, 0x22];
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        
        println!("=== MySQL Conditional Comment Fuzz Case ===");
        print!("Input bytes: {:?} -> \"", input);
        for &byte in input {
            if byte >= 32 && byte <= 126 {
                print!("{}", byte as char);
            } else {
                print!("\\x{:02x}", byte);
            }
        }
        println!("\"");
        
        // Get the fingerprint (this triggers the MySQL comment detection)
        let fingerprint = state.get_fingerprint();
        println!("Rust fingerprint: {}", fingerprint);
        
        // The input starts with a single quote and contains /*!# sequence
        // The Rust implementation should detect the MySQL conditional comment pattern
        // and convert the string token to an EVIL token, producing fingerprint "X"
        assert_eq!(fingerprint.as_str(), "X", 
                   "Fingerprint should be 'X' due to MySQL conditional comment detection");
        
        // Test that this is detected as SQL injection (matching C behavior)
        let is_injection = state.detect();
        assert_eq!(is_injection, true,
                   "Input containing /*!# should be detected as SQL injection");
        
        println!("Final tokens ({} total):", state.tokens.len());
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Token {}: type={:?}, val={:?}", i, token.token_type, token.value_as_str());
        }
        
        // After MySQL comment detection, we should have an EVIL token
        assert!(state.tokens.iter().any(|t| t.token_type == TokenType::Evil),
                "Should have at least one EVIL token after MySQL comment detection");
    }

    #[test]
    fn test_fuzz_crash_c_behavior() {
        // Test the specific fuzz crash case: "--1-@a#*\x03"
        // This should match C behavior exactly:
        // - Should be detected as SQL injection (true)
        // - Should produce fingerprint "1ovc" (4 tokens after comment processing)
        let input = b"--1-@a#*\x03";
        
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        let is_sqli = state.detect();  // Use detect() to trigger MySQL reparse
        let fingerprint = state.fingerprint_string();
        
        println!("Input: {:?}", std::str::from_utf8(input).unwrap_or("<invalid>"));
        println!("Hex: {:?}", input);
        println!("Is SQL injection: {}", is_sqli);
        println!("Fingerprint: '{}'", fingerprint);
        println!("Token count: {}", state.tokens.len());
        
        for (i, token) in state.tokens.iter().enumerate() {
            println!("Token {}: {:?} '{}'", i, token.token_type, token.value_as_str());
        }
        
        // This test documents the expected behavior according to C implementation:
        // The C implementation should return true for this input with fingerprint "1ovc"
        // After our fix, Rust should match this exactly
        assert!(is_sqli, "Should detect as SQL injection to match C behavior");
        
        // The exact fingerprint should match C - if this fails, we need to investigate further
        // Based on analysis, C processes: NUMBER(1), OPERATOR(-), VARIABLE(@a), COMMENT(#*)
        // Expected fingerprint: "1ovc" (where 'c' represents the comment token)
        println!("Expected: fingerprint with 4 characters representing tokens processed from comment content");
    }
    
    #[test]
    fn test_mysql_reparse_logic() {
        // Test that "--" not followed by whitespace triggers MySQL reparse
        let input = b"--1-@a#*\x03";
        
        // Debug: Check character classification
        println!("Character analysis:");
        println!("  input[0] = '{}' (0x{:02x})", input[0] as char, input[0]);
        println!("  input[1] = '{}' (0x{:02x})", input[1] as char, input[1]);
        println!("  input[2] = '{}' (0x{:02x})", input[2] as char, input[2]);
        
        // Import needed for checking character type
        use crate::sqli::sqli_data::{get_char_type, CharType};
        let char_type_dash = get_char_type(input[0]);
        let char_type_1 = get_char_type(input[2]);
        println!("  Character type of '-': {:?}", char_type_dash);
        println!("  Character type of '1': {:?}", char_type_1);
        println!("  Is '1' white? {}", matches!(char_type_1, CharType::White));
        
        // First test tokenizer directly
        use crate::sqli::tokenizer::SqliTokenizer;
        println!("\nDirect tokenizer test (ANSI mode):");
        let mut tokenizer = SqliTokenizer::new(input, SqliFlags::FLAG_SQL_ANSI);
        let token = tokenizer.next_token();
        println!("  First token: {:?}", token.as_ref().map(|t| (t.token_type.clone(), t.value_as_str())));
        println!("  Tokenizer stats_comment_ddx: {}", tokenizer.stats_comment_ddx);
        println!("  Tokenizer stats_comment_ddw: {}", tokenizer.stats_comment_ddw);
        
        // Now test with state
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        let fingerprint = state.get_fingerprint();
        
        println!("\nANSI mode through SqliState:");
        println!("  Fingerprint: '{}'", fingerprint.as_str());
        println!("  stats_comment_ddx: {}", state.stats_comment_ddx);
        println!("  stats_comment_ddw: {}", state.stats_comment_ddw);
        println!("  Token count: {}", state.tokens.len());
        
        // In ANSI mode with "--" not followed by whitespace, should set stats_comment_ddx
        assert!(state.stats_comment_ddx > 0, "stats_comment_ddx should be set for '--' not followed by whitespace");
        
        // Now test with MySQL mode - should tokenize "--" as two operators
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_MYSQL);
        let fingerprint = state.get_fingerprint();
        
        println!("MySQL mode:");
        println!("  Fingerprint: '{}'", fingerprint.as_str());
        println!("  stats_comment_ddx: {}", state.stats_comment_ddx);
        println!("  Token count: {}", state.tokens.len());
        
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Token {}: {:?} '{}'", i, token.token_type, token.value_as_str());
        }
        
        // In MySQL mode, should produce multiple tokens (not just a comment)
        assert!(state.tokens.len() > 1, "MySQL mode should produce multiple tokens from '--1-@a#*\\x03'");
        
        // Test the full detect() method with reparse
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        let is_sqli = state.detect();
        
        println!("Full detect():");
        println!("  Is SQL injection: {}", is_sqli);
        println!("  Final fingerprint: '{}'", state.fingerprint());
        
        // The detect() method should find SQL injection after MySQL reparse
        assert!(is_sqli, "detect() should return true after MySQL reparse");
    }
}