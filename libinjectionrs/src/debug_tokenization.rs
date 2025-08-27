use crate::sqli::*;

#[test]
fn debug_raw_tokenization() {
    let input = r#"{``.``.id} UNION SELECT TABLE"#;
    println!("=== Raw Tokenization Debug ===");
    println!("Input: '{}'", input);
    println!("Input bytes: {:?}", input.as_bytes());
    
    // Create a new state and do tokenization step by step manually
    let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    
    // We need to call the tokenization logic similar to fold_tokens but with debug output
    println!("\n=== Manual Tokenization ===");
    let mut tokenizer = SqliTokenizer::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    let mut tokens_found = 0;
    
    while tokens_found < 10 {
        if let Some(token) = tokenizer.next_token() {
            println!("  Found token {}: {:?} '{}' (pos: {}, len: {}) raw: {:?}",
                    tokens_found, token.token_type, token.value_as_str(), 
                    token.pos, token.len, &token.val[..token.len.min(8)]);
            state.tokens.push(token);
            tokens_found += 1;
        } else {
            println!("  No more tokens");
            break;
        }
    }
    
    println!("\n=== Final tokens ===");
    for (i, token) in state.tokens.iter().enumerate() {
        println!("  {}: {:?} '{}' (pos: {}, len: {}) raw: {:?}",
                i, token.token_type, token.value_as_str(), token.pos, token.len,
                &token.val[..token.len.min(16)]);
    }
}