use crate::sqli::*;

#[test]
fn debug_test_115() {
    let input = r#"{``.``.id} UNION SELECT TABLE"#;
    println!("=== Debug test-folding-115 ===");
    println!("Input: '{}'", input);
    println!("Input length: {}", input.len());
    
    // Test folding
    println!("\n=== Folding ===");
    let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    let token_count = state.fold_tokens();
    
    println!("Folded tokens ({}): ", token_count);
    for (i, token) in state.tokens.iter().enumerate() {
        if i >= token_count {
            break;
        }
        println!("  {}: {:?} '{}' (len: {}, pos: {}) raw_val: {:?}", 
                i, token.token_type, token.value_as_str(), token.len, token.pos, &token.val[..token.len.min(8)]);
    }
    
    // Test with C comparison
    println!("\n=== Expected vs Actual ===");
    println!("Expected (from C):");
    println!("  {{ {{");  // Should be left brace then space then left brace  
    println!("  X");
    println!("Actual (from Rust):");
    if token_count > 0 {
        for (i, token) in state.tokens.iter().enumerate() {
            if i >= token_count {
                break;
            }
            let value_str = token.value_as_str();
            if value_str.is_empty() {
                println!("  {} <empty>", token.token_type.to_char());
            } else {
                println!("  {} {}", token.token_type.to_char(), value_str);
            }
        }
    } else {
        println!("  <no tokens>");
    }
    
    // Test what happens with tokenization vs folding flags
    println!("\n=== Testing with different flags ===");
    let mut state_ansi = SqliState::new(input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
    let token_count_ansi = state_ansi.fold_tokens();
    println!("With FLAG_SQL_ANSI: {} tokens", token_count_ansi);
    for (i, token) in state_ansi.tokens.iter().enumerate() {
        if i >= token_count_ansi {
            break;
        }
        println!("  {} {}", token.token_type.to_char(), token.value_as_str());
    }
}