#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqli::{SqliDetector, SqliResult};
    
    #[test]
    fn test_basic_tokenization() {
        let input = b"SELECT * FROM users WHERE id = 1";
        let detector = SqliDetector::new();
        let result = detector.detect(input);
        
        println!("Basic SQL: {:?}", result);
        
        // Should be safe SQL
        match result {
            SqliResult::Safe => {},
            SqliResult::Injection { .. } => panic!("False positive on basic SQL"),
        }
    }
    
    #[test]
    fn test_simple_injection() {
        let input = b"1 OR 1=1";
        let detector = SqliDetector::new();
        let result = detector.detect(input);
        
        println!("Simple injection: {:?}", result);
        
        // Should detect injection
        match result {
            SqliResult::Injection { .. } => {},
            SqliResult::Safe => panic!("False negative on simple injection"),
        }
    }
    
    #[test]
    fn test_union_injection() {
        let input = b"1 UNION SELECT password FROM users";
        let detector = SqliDetector::new();
        let result = detector.detect(input);
        
        println!("UNION injection: {:?}", result);
        
        // Should detect injection
        match result {
            SqliResult::Injection { .. } => {},
            SqliResult::Safe => panic!("False negative on UNION injection"),
        }
    }
    
    #[test]
    fn test_tokenizer_whitespace() {
        use crate::sqli::sqli_tokenizer::char_is_white;
        
        assert!(char_is_white(b' '));
        assert!(char_is_white(b'\t'));
        assert!(char_is_white(b'\n'));
        assert!(char_is_white(b'\r'));
        assert!(!char_is_white(b'a'));
        assert!(!char_is_white(b'1'));
    }
    
    #[test]
    fn test_tokenizer_digits() {
        use crate::sqli::sqli_tokenizer::is_digit;
        
        assert!(is_digit(b'0'));
        assert!(is_digit(b'5'));
        assert!(is_digit(b'9'));
        assert!(!is_digit(b'a'));
        assert!(!is_digit(b' '));
    }
    
    #[test]
    fn test_token_creation() {
        use crate::sqli::Token;
        
        let token = Token::new(b'k', 0, b"SELECT");
        assert_eq!(token.pos, 0);
        assert_eq!(token.len, 6);
        assert_eq!(token.value_slice(), b"SELECT");
        
        let char_token = Token::new_char(b'(', 5, b'(');
        assert_eq!(char_token.pos, 5);
        assert_eq!(char_token.len, 1);
        assert_eq!(char_token.value_slice(), b"(");
    }
}