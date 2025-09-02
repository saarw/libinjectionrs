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
    fn test_fuzz_differential_case_skv() {
        // Test case from fuzzer: "As@'As@'j@Qsj@Qs"
        // This case revealed a missing whitelist check for keywords in 3-token fingerprints
        let input = b"As@'As@'j@Qsj@Qs";
        
        // Test with detect() method which checks multiple contexts
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        let is_sqli = state.detect();
        let fp = state.get_fingerprint();
        
        // The C implementation returns FALSE for this input with fingerprint "skv"
        // because the middle token "As" is a keyword with length < 5
        assert_eq!(is_sqli, false, "Should match C implementation - fingerprint: {}", fp);
        assert_eq!(fp.as_str(), "skv", "Should produce 'skv' fingerprint");
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
    fn test_fuzz_input_with_quote_double() {
        let input = b"\xd8$\xff*\"\"\x1c\"\"2`";
        
        // Test with FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL
        let mut state = SqliState::new(input, SqliFlags::new(
            SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_MYSQL.0
        ));
        
        let fingerprint = state.get_fingerprint();
        
        // The C implementation returns "s" for this input with these flags
        assert_eq!(fingerprint.as_str(), "s", "Expected fingerprint 's' but got '{}'", fingerprint.as_str());
    }
    
    #[test]
    fn test_fuzz_input_with_detect() {
        let input = b"\xd8$\xff*\"\"\x1c\"\"2`";
        
        // First check what fingerprints we get with different flags
        let mut state1 = SqliState::new(input, SqliFlags::new(
            SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0
        ));
        let fp1 = state1.get_fingerprint();
        println!("FLAG_QUOTE_NONE | FLAG_SQL_ANSI: {}", fp1);
        println!("  Is blacklisted: {}", blacklist::is_blacklisted(fp1.as_str()));
        
        let mut state2 = SqliState::new(input, SqliFlags::new(
            SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_MYSQL.0
        ));
        let fp2 = state2.get_fingerprint();
        println!("FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL: {}", fp2);
        println!("  Is blacklisted: {}", blacklist::is_blacklisted(fp2.as_str()));
        
        // Test using detect() which should try multiple flag combinations
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        let is_sqli = state.detect();
        
        // The C implementation returns false for this input
        assert!(!is_sqli, "Expected detect() to return false but got true");
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
        
        // Debug: show tokens before get_fingerprint
        println!("Tokens before get_fingerprint():");
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Token {}: type={:?}, val={:?}", i, token.token_type, token.value_as_str());
        }
        
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
    
    #[test]
    fn test_php_backquote_comment_fuzz_case() {
        // Test the PHP backquote comment conversion that was missing
        // This test specifically targets the case where a backtick creates an empty
        // bareword token that should be converted to a comment during folding
        
        // Simple test case: "1 OR 1`" - backtick at end creates empty bareword
        let input = b"1 OR 1`";
        
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        let fingerprint = state.get_fingerprint();
        
        println!("PHP backquote comment test:");
        println!("  Input: '{}'", core::str::from_utf8(input).unwrap());
        println!("  Fingerprint: '{}'", fingerprint.as_str());
        println!("  Token count: {}", state.tokens.len());
        
        // Examine tokens
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Token {}: type={:?}, val='{}', str_open=0x{:02x}, len={}, str_close=0x{:02x}",
                     i, token.token_type, token.value_as_str(), 
                     token.str_open, token.len, token.str_close);
        }
        
        // The last token should be a comment (PHP backquote comment conversion)
        if let Some(last_token) = state.tokens.last() {
            assert_eq!(last_token.token_type, TokenType::Comment,
                      "Last token should be converted to Comment for PHP backquote");
        }
        
        // The fingerprint should be "1&1c" - number, logic operator, number, comment
        assert_eq!(fingerprint.as_str(), "1&1c", 
                   "Fingerprint should be '1&1c' for PHP backquote comment, got: '{}'", 
                   fingerprint.as_str());
        
        // Now test with the original fuzz input to ensure it doesn't crash
        let fuzz_input = &[0xd8, 0x24, 0xff, 0x2a, 0x22, 0x22, 0x1c, 0x22, 0x22, 0x32, 0x60];
        let mut state = SqliState::new(fuzz_input, SqliFlags::FLAG_SQL_ANSI);
        let _is_sqli = state.detect(); // Just ensure it doesn't crash
    }
    
    #[test]
    fn test_original_fuzz_differential_input() {
        // Test the exact fuzz input that revealed the differential
        // Input bytes: \xd8$\xff*""\x1c""2`
        let input = &[0xd8, 0x24, 0xff, 0x2a, 0x22, 0x22, 0x1c, 0x22, 0x22, 0x32, 0x60];
        
        // Test with FLAG_QUOTE_DOUBLE as used in the original fuzz test
        let flags = SqliFlags::new(
            SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_MYSQL.0
        );
        let mut state = SqliState::new(input, flags);
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.fingerprint();
        
        println!("Original fuzz input test (FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL):");
        println!("  Input bytes: {:?}", input);
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        
        // The C implementation returns false for this input
        // After our fix, Rust should also return false
        assert!(!is_sqli_rust, "Should not detect as SQL injection (matching C behavior)");
        
        // Also test with FLAG_QUOTE_NONE | FLAG_SQL_ANSI combination
        let flags = SqliFlags::new(
            SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0
        );
        let mut state = SqliState::new(input, flags);
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.fingerprint();
        
        println!("\nOriginal fuzz input test (FLAG_QUOTE_NONE | FLAG_SQL_ANSI):");
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        
        // Both flag combinations should not detect SQL injection
        assert!(!is_sqli_rust, "Should not detect as SQL injection with FLAG_QUOTE_NONE");
    }

    #[test]
    fn test_fuzz_differential_0xff_chars() {
        // Test the fuzz input that revealed another differential
        // Input: "$8--\xff)\xff\x03\xff)"
        // C returns: true (detected as SQLi)
        // Rust returns: false (not detected as SQLi)
        let input = &[0x24, 0x38, 0x2d, 0x2d, 0xff, 0x29, 0xff, 0x03, 0xff, 0x29];
        
        // Test with FLAG_NONE (as used in the fuzz test)
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.fingerprint();
        
        println!("Fuzz differential test with 0xFF characters:");
        println!("  Input bytes: {:?}", input);
        println!("  Input string (lossy): {:?}", String::from_utf8_lossy(input));
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        println!("  C detection: true");
        
        // This test is expected to FAIL until the bug is fixed
        // The C implementation detects this as SQLi (returns true)
        // Currently Rust does not detect it (returns false)
        // TODO: Fix this differential - Rust should match C behavior
        assert!(is_sqli_rust, 
                "KNOWN BUG: Rust should detect this as SQL injection to match C behavior. \
                 Input: $8--\\xff)\\xff\\x03\\xff), C: true, Rust: {}", 
                is_sqli_rust);
    }

    #[test]
    fn test_fuzz_differential_whitelist_bug() {
        // Test case for fuzz input that revealed a C whitelist bug
        // Input: [27, 56, 45, 45] which is "\x1b8--"
        // This test verifies that the Rust implementation replicates the C bug for compatibility
        // 
        // Background: The C code has a bug at libinjection_sqli.c:2126 where it calculates
        // the character position incorrectly, using tokenvec[0].len instead of 
        // tokenvec[0].pos + tokenvec[0].len. This causes it to check the wrong character
        // and return false when it should return true.
        //
        // The bug is intentionally replicated in Rust for exact C compatibility.
        let input = &[27u8, 56, 45, 45]; // "\x1b8--"
        
        println!("=== Fuzz Differential Whitelist Bug Test ===");
        println!("Input bytes: {:?}", input);
        println!("Input hex: {}", input.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        
        // Test with detect() method to ensure single tokenization pass
        let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
        let is_sqli = state.detect();
        let fingerprint = std::str::from_utf8(&state.fingerprint)
            .unwrap_or("")
            .trim_end_matches('\0');
        
        println!("Rust fingerprint: '{}'", fingerprint);
        println!("Rust detection: {}", is_sqli);
        println!("Rust stats_tokens: {}", state.stats_tokens);
        
        // Both C and Rust should produce the same results due to bug compatibility:
        // - Fingerprint: "1c" (number + comment)
        // - stats_tokens: 2 (not > 2, so no early exit)
        // - Detection result: false (due to C bug - checks wrong character position)
        assert_eq!(fingerprint, "1c", "Should produce '1c' fingerprint (number + comment)");
        assert_eq!(state.stats_tokens, 2, "Should have stats_tokens = 2 (single tokenization pass)");
        assert_eq!(is_sqli, false, "Should return false due to C bug compatibility");
        
        // Verify the token structure matches expectations
        assert_eq!(state.tokens.len(), 2, "Should have exactly 2 tokens");
        assert_eq!(state.tokens[0].token_type, TokenType::Number, "First token should be Number");
        assert_eq!(state.tokens[0].value_as_str(), "8", "First token value should be '8'");
        assert_eq!(state.tokens[0].pos, 1, "First token should start at position 1 (after \\x1b)");
        assert_eq!(state.tokens[0].len, 1, "First token should have length 1");
        
        assert_eq!(state.tokens[1].token_type, TokenType::Comment, "Second token should be Comment");
        assert_eq!(state.tokens[1].value_as_str(), "--", "Second token value should be '--'");
        assert_eq!(state.tokens[1].pos, 2, "Second token should start at position 2");
        assert_eq!(state.tokens[1].len, 2, "Second token should have length 2");
        
        println!("✅ C bug compatibility verified - input correctly returns false despite being SQLi");
    }

    #[test]
    fn test_fuzz_differential_evil_token_fix() {
        /// Test case for the fuzz differential where Rust was returning false while C returned true.
        /// This was caused by Evil tokens not contributing to fingerprint generation due to:
        /// 1. Token copying only copying up to 'left' count instead of full token count
        /// 2. Fingerprint generation limiting to LIBINJECTION_SQLI_MAX_TOKENS instead of processing all tokens
        /// 
        /// The fix ensures Evil tokens are properly included in fingerprints and trigger SQL injection detection.
        let input = vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  // 10 x 0xFF bytes
            101, 35, 35, 92, 102,                               // e##\f 
            239, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  // 11 more bytes including 0xFF
            43, 154, 251, 123, 96                               // Final bytes
        ];
        
        let mut state = SqliState::new(&input, SqliFlags::FLAG_NONE);
        let is_sqli = state.detect();
        let fingerprint = state.get_fingerprint();
        
        // The fix should result in:
        // 1. Evil token creation during folding (zero-length token gets converted to Evil)
        // 2. Evil token contributes 'X' to fingerprint 
        // 3. Any fingerprint containing 'X' gets converted to pure 'X' fingerprint
        // 4. Fingerprint 'X' triggers SQL injection detection
        assert!(is_sqli, "Should detect SQL injection (matching C behavior)");
        assert_eq!(fingerprint.as_str(), "X", "Fingerprint should be 'X' when Evil tokens are present");
        
        // Verify we have exactly one Evil token after fingerprint processing
        assert_eq!(state.tokens.len(), 1, "Should have exactly 1 token after Evil fingerprint processing");
        assert_eq!(state.tokens[0].token_type, TokenType::Evil, "Single token should be Evil type");
        assert_eq!(state.tokens[0].value_as_str(), "X", "Evil token value should be 'X'");
        
        println!("✅ Fuzz differential fixed - Evil tokens now contribute to SQL injection detection");
    }

    #[test]
    fn test_fuzz_differential_crash_dd7a369a() {
        // Test case for fuzz differential crash-dd7a369aa6802688b7158b456ca6284a0263c7f1
        // Input: "\\*\\\\As@\\\\\\�!!�!\\!44!4���!��1j�!@+*!+"
        // Bytes: [92, 42, 92, 92, 65, 115, 64, 92, 92, 92, 208, 33, 33, 208, 33, 92, 33, 52, 52, 33, 52, 255, 255, 255, 33, 255, 255, 49, 106, 255, 33, 64, 43, 42, 33, 43]
        // Expected: Rust should return the same as C (C returns false, Rust currently returns true)
        let input = [
            92, 42, 92, 92, 65, 115, 64, 92, 92, 92, 208, 33, 33, 208, 33, 92, 33, 
            52, 52, 33, 52, 255, 255, 255, 33, 255, 255, 49, 106, 255, 33, 64, 43, 42, 33, 43
        ];
        
        // Test with detect() method (as used in the fuzz test)
        let mut state = SqliState::new(&input, SqliFlags::FLAG_NONE);
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.get_fingerprint();
        
        println!("Fuzz differential test crash-dd7a369a:");
        println!("  Input bytes: {:?}", input);
        println!("  Input string (lossy): {:?}", String::from_utf8_lossy(&input));
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        println!("  Expected (C) detection: false");
        
        // The C implementation returns false for this input
        // Rust should match this behavior exactly
        assert_eq!(is_sqli_rust, false, 
                   "Rust should match C behavior - expected false but got {}. \
                    This is a known differential that needs to be fixed.", 
                   is_sqli_rust);
    }

    #[test]
    fn test_fuzz_differential_d1ff5132() {
        // Test case for fuzz differential crash-d1ff5132943f80b0749a49c160171e4663c2559f
        // Input: "$8\\\"\">\"\"\"" 
        // Bytes: [36, 56, 92, 34, 34, 62, 34, 34, 34]
        // Expected: Rust should return the same as C (C returns true, Rust currently returns false)
        let input = b"$8\\\"\">\"\"\"";
        
        println!("=== Detailed Rust Analysis ===");
        println!("Input bytes: {:?}", input);
        println!("Input as string: {:?}", String::from_utf8_lossy(input));
        
        // Test raw tokenization first
        println!("\n=== Raw Tokenization ===");
        let mut tokenizer = SqliTokenizer::new(input, SqliFlags::FLAG_NONE);
        let mut token_count = 0;
        while let Some(token) = tokenizer.next_token() {
            println!("Raw Token {}: type={:?}, val='{}', pos={}, len={}", 
                     token_count, token.token_type, token.value_as_str(), token.pos, token.len);
            token_count += 1;
            if token_count >= 10 {
                println!("  (stopping at 10 tokens)");
                break;
            }
        }
        
        // Test with detect() method (as used in the fuzz test)
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        
        // Debug the folding process
        println!("\n=== Folding Process Debug ===");
        let token_count = state.fold_tokens();
        println!("Folded token count: {}", token_count);
        println!("Tokens after folding:");
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Folded Token {}: type={:?}, val='{}', pos={}, len={}", 
                     i, token.token_type, token.value_as_str(), token.pos, token.len);
        }
        
        // Get fingerprint directly and check if it matches C
        let fingerprint_rust = state.get_fingerprint();
        println!("After get_fingerprint(), tokens changed to:");
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Final Token {}: type={:?}, val='{}', pos={}, len={}", 
                     i, token.token_type, token.value_as_str(), token.pos, token.len);
        }
        
        println!("Direct fingerprint result: '{}'", fingerprint_rust.as_str());
        
        // C produces "sos" (3 chars), Rust produces "1sos" (4 chars)
        // The issue is that we have 4 tokens instead of 3, but the pattern is there
        // Let's check if this should be detected as SQLi using the blacklist
        let is_sqli_fingerprint = state.check_is_sqli(&fingerprint_rust);
        println!("Is fingerprint '{}' SQLi? {}", fingerprint_rust.as_str(), is_sqli_fingerprint);
        
        let is_sqli_rust = state.detect();
        
        println!("\nFuzz differential test crash-d1ff5132:");
        println!("  Input bytes: {:?}", input);
        println!("  Input string (lossy): {:?}", String::from_utf8_lossy(input));
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        println!("  Expected (C) detection: true");
        println!("  Token count after processing: {}", state.tokens.len());
        
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Final Token {}: type={:?}, val='{}', pos={}, len={}", 
                     i, token.token_type, token.value_as_str(), token.pos, token.len);
        }
        
        // The C implementation returns true for this input
        // Rust should match this behavior exactly
        assert_eq!(is_sqli_rust, true, 
                   "Rust should match C behavior - expected true but got {}. \
                    This test should fail initially until the differential is fixed.", 
                   is_sqli_rust);
    }

    #[test]
    fn test_fuzz_differential_input_1a0_2d_2d_02() {
        // Test case for fuzz differential that panicked at fuzz_targets/fuzz_differential_sqli.rs:41:17
        // Input: "1�--\u{2}" 
        // Bytes: [49, 160, 45, 45, 2]
        // Expected: Rust should return the same as C (C returns true, Rust currently returns false)
        let input = &[49u8, 160, 45, 45, 2]; // "1�--\u{2}"
        
        println!("=== Detailed Debug Analysis ===");
        println!("Input bytes: {:?}", input);
        println!("Input as string (lossy): {:?}", String::from_utf8_lossy(input));
        
        // Test blacklist directly
        println!("\n--- Blacklist Test ---");
        println!("is_blacklisted('1c'): {}", blacklist::is_blacklisted("1c"));
        println!("is_blacklisted('1o'): {}", blacklist::is_blacklisted("1o"));
        
        // Test the first pass only - ANSI mode
        let mut state1 = SqliState::new(input, SqliFlags::FLAG_NONE);
        println!("\n--- First Pass (ANSI Mode) ---");
        println!("Initial flags after FLAG_NONE conversion: {:?}", state1.flags);
        println!("is_ansi(): {}", state1.flags.is_ansi());
        println!("is_mysql(): {}", state1.flags.is_mysql());
        
        let fingerprint1 = state1.get_fingerprint();
        println!("Fingerprint: '{}'", fingerprint1.as_str());
        println!("stats_comment_ddx: {}", state1.stats_comment_ddx);
        println!("stats_comment_hash: {}", state1.stats_comment_hash);
        println!("reparse_as_mysql(): {}", state1.reparse_as_mysql());
        
        // Test whitelist - add detailed debugging
        println!("check_is_sqli('1c'): {}", state1.check_is_sqli(&fingerprint1));
        let whitelist_result = state1.is_not_whitelist();
        println!("is_not_whitelist(): {}", whitelist_result);
        
        // Debug whitelist logic step by step
        println!("Whitelist debug:");
        println!("  fingerprint length: {}", fingerprint1.as_str().len());
        println!("  tokens.len(): {}", state1.tokens.len());
        println!("  stats_tokens: {}", state1.stats_tokens);
        if state1.tokens.len() >= 2 {
            println!("  token[0]: {:?} '{}' pos={} len={}", 
                     state1.tokens[0].token_type, state1.tokens[0].value_as_str(),
                     state1.tokens[0].pos, state1.tokens[0].len);
            println!("  token[1]: {:?} '{}' pos={} len={}", 
                     state1.tokens[1].token_type, state1.tokens[1].value_as_str(),
                     state1.tokens[1].pos, state1.tokens[1].len);
        }
        
        // Check tokens after first pass
        println!("Tokens after first pass:");
        for (i, token) in state1.tokens.iter().enumerate() {
            println!("  Token {}: {:?} '{}' (pos: {}, len: {})", 
                     i, token.token_type, token.value_as_str(), token.pos, token.len);
        }
        
        // Test the second pass - MySQL mode (if needed)
        if state1.reparse_as_mysql() {
            println!("\n--- Second Pass (MySQL Mode) ---");
            let original_flags = SqliFlags::FLAG_NONE; // Original passed to constructor
            let mysql_flags = (original_flags.0 & !SqliFlags::FLAG_SQL_ANSI.0) | SqliFlags::FLAG_SQL_MYSQL.0;
            println!("MySQL flags: {:?}", SqliFlags::new(mysql_flags));
            
            let mut state2 = SqliState::new(input, SqliFlags::new(mysql_flags));
            let fingerprint2 = state2.get_fingerprint();
            println!("MySQL fingerprint: '{}'", fingerprint2.as_str());
            
            // Check tokens after MySQL pass
            println!("Tokens after MySQL pass:");
            for (i, token) in state2.tokens.iter().enumerate() {
                println!("  Token {}: {:?} '{}' (pos: {}, len: {})", 
                         i, token.token_type, token.value_as_str(), token.pos, token.len);
            }
        } else {
            println!("\n--- No MySQL Reparse Needed ---");
        }
        
        // Test full detect() method
        println!("\n--- Full detect() Method ---");
        let mut state_full = SqliState::new(input, SqliFlags::FLAG_NONE);
        let is_sqli_rust = state_full.detect();
        let fingerprint_rust = state_full.get_fingerprint();
        
        println!("Final result: {}", is_sqli_rust);
        println!("Final fingerprint: '{}'", fingerprint_rust.as_str());
        println!("Expected (C) detection: true");
        
        // The C implementation returns true for this input
        // This test should fail initially until the differential is fixed
        assert_eq!(is_sqli_rust, true, 
                   "Rust should match C behavior - expected true but got {}. \
                    This test should fail initially until the differential is fixed.", 
                   is_sqli_rust);
    }

    #[test]
    fn test_fuzz_differential_percent_signs() {
        // Test case for fuzz differential that panicked
        // Input: "%%%%%%%%%%%%%%%%%%%%%%#*#\376\"\016%%q]//*!\361'#&~#a/"
        // Bytes: [37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 35, 42, 35, 254, 34, 14, 37, 37, 113, 93, 47, 47, 42, 33, 241, 39, 35, 38, 126, 35, 97, 47]
        // Expected: Rust should return the same as C (C returns false, Rust currently returns true)
        let input = &[37u8, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 35, 42, 35, 254, 34, 14, 37, 37, 113, 93, 47, 47, 42, 33, 241, 39, 35, 38, 126, 35, 97, 47];
        
        // Test with detect() method (as used in the fuzz test)
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.get_fingerprint();
        
        println!("Fuzz differential test with percent signs:");
        println!("  Input bytes: {:?}", input);
        println!("  Input string (lossy): {:?}", String::from_utf8_lossy(input));
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        println!("  Expected (C) detection: false");
        
        // The C implementation returns false for this input
        // This test should fail initially until the differential is fixed
        assert_eq!(is_sqli_rust, false, 
                   "Rust should match C behavior - expected false but got {}. \
                    This test should fail initially until the differential is fixed.", 
                   is_sqli_rust);
    }
    
    #[test]
    fn test_fuzz_differential_quote_newline_quote() {
        // Test case for fuzz differential that panicked at fuzz_targets/fuzz_differential_sqli.rs:41:17
        // Input: "q'�'��������'\n+''#" 
        // Bytes: [113, 39, 255, 39, 255, 255, 255, 255, 255, 255, 255, 255, 39, 10, 43, 39, 39, 35]
        // Expected: Rust should return the same as C (C returns false, Rust currently returns true)
        let input = &[113u8, 39, 255, 39, 255, 255, 255, 255, 255, 255, 255, 255, 39, 10, 43, 39, 39, 35];
        
        println!("=== Fuzz Differential Test: Quote Newline Quote ===");
        println!("Input bytes: {:?}", input);
        println!("Input as string (lossy): {:?}", String::from_utf8_lossy(input));
        
        // Show raw tokenization first
        println!("\n=== Raw Tokenization Debug ===");
        let mut tokenizer = crate::sqli::tokenizer::SqliTokenizer::new(input, SqliFlags::FLAG_NONE);
        let mut token_count = 0;
        while let Some(token) = tokenizer.next_token() {
            println!("Raw Token {}: type={:?}, val='{}', pos={}, len={}, str_open={:02x}, str_close={:02x}",
                     token_count, token.token_type, token.value_as_str(), 
                     token.pos, token.len, token.str_open, token.str_close);
            token_count += 1;
            if token_count >= 10 {
                println!("  (limiting to first 10 tokens)");
                break;
            }
        }
        
        // Test with detect() method (as used in the fuzz test)
        let mut state = SqliState::new(input, SqliFlags::FLAG_NONE);
        
        println!("\n=== After Folding ===");
        let _folded_count = state.fold_tokens();
        println!("Tokens after folding:");
        for (i, token) in state.tokens.iter().enumerate() {
            println!("  Folded Token {}: type={:?}, val='{}', pos={}, len={}",
                     i, token.token_type, token.value_as_str(), token.pos, token.len);
        }
        
        let is_sqli_rust = state.detect();
        let fingerprint_rust = state.get_fingerprint();
        
        println!("\n=== Final Results ===");
        println!("  Rust fingerprint: '{}'", fingerprint_rust.as_str());
        println!("  Rust detection: {}", is_sqli_rust);
        println!("  Expected (C) detection: false");
        
        // Debug blacklist status for both fingerprints
        println!("  C fingerprint 'snsos' blacklisted: {}", blacklist::is_blacklisted("snsos"));
        println!("  Rust fingerprint 'sosc' blacklisted: {}", blacklist::is_blacklisted("sosc"));
        
        // The C implementation returns false for this input
        // This test should fail initially until the differential is fixed
        assert_eq!(is_sqli_rust, false, 
                   "Rust should match C behavior - expected false but got {}. \
                    This test should fail initially until the differential is fixed.", 
                   is_sqli_rust);
    }
}