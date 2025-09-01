// SQL injection detection tests

#[cfg(test)]
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
        assert!(fingerprint.as_str().len() >= 0);
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
}