use crate::sqli::*;

#[test]
fn debug_folding_115() {
    let input = r#"{``.``.id} UNION SELECT TABLE"#;
    println!("=== Folding Debug for test-folding-115 ===");
    println!("Input: '{}'", input);
    
    let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    
    // First, do the same tokenization as before to see what we get
    let mut tokenizer = SqliTokenizer::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    let mut tokens = Vec::new();
    
    while let Some(token) = tokenizer.next_token() {
        tokens.push(token);
        if tokens.len() >= 10 { break; }
    }
    
    println!("\n=== Raw tokens ===");
    for (i, token) in tokens.iter().enumerate() {
        println!("  {}: {:?} '{}' (pos: {}, len: {})",
                i, token.token_type, token.value_as_str(), token.pos, token.len);
    }
    
    // Now test the folding with step-by-step debug output
    println!("\n=== Testing specific folding case ===");
    if tokens.len() >= 2 {
        let first_token = &tokens[0];
        let second_token = &tokens[1];
        
        println!("First token: {:?} '{}' (len: {})", 
                first_token.token_type, first_token.value_as_str(), first_token.len);
        println!("Second token: {:?} '{}' (len: {})", 
                second_token.token_type, second_token.value_as_str(), second_token.len);
        
        // Check the exact condition from C code
        if first_token.token_type == TokenType::LeftBrace &&
           second_token.token_type == TokenType::Bareword {
            println!("✓ Found LeftBrace + Bareword pattern");
            
            if second_token.len == 0 {
                println!("✓ Bareword has zero length - should trigger Evil marking");
                println!("  This should be marked as TokenType::Evil");
            } else {
                println!("✗ Bareword has length {} - not zero", second_token.len);
            }
        } else {
            println!("✗ Pattern doesn't match LeftBrace + Bareword");
        }
    }
    
    // Now run the actual folding
    println!("\n=== Running fold_tokens ===");
    let token_count = state.fold_tokens();
    
    println!("Folding result: {} tokens", token_count);
    println!("state.tokens.len(): {}", state.tokens.len());
    for i in 0..state.tokens.len() {
        let token = &state.tokens[i];
        println!("  {}: {:?} '{}' (len: {})", 
                i, token.token_type, token.value_as_str(), token.len);
    }
    
    // Check if we got the expected result
    if token_count >= 2 && state.tokens.len() >= 2 {
        let first_folded = &state.tokens[0];
        let second_folded = &state.tokens[1];
        
        println!("\n=== Expected vs Actual ===");
        println!("Expected: LeftBrace '{{' and Evil ''");
        println!("Actual: {:?} '{}' and {:?} '{}'", 
                first_folded.token_type, first_folded.value_as_str(),
                second_folded.token_type, second_folded.value_as_str());
    }
}