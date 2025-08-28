use libinjectionrs::sqli::{SqliState, SqliFlags, SqliTokenizer};

fn main() {
    let input = "SELECT float @@version;";
    println!("Input: {}", input);
    println!("Testing Rust tokenization behavior...\n");
    
    // Create SqliState and debug the tokenization process
    let mut state = SqliState::from_string(input, SqliFlags::FLAG_SQL_ANSI);
    
    // Get the fingerprint which will cause tokenization and folding to occur
    let fingerprint = state.get_fingerprint();
    
    println!("=== Raw Tokens After Folding ===");
    for (i, token) in state.tokens.iter().enumerate() {
        println!("Token {}: type={:?} ({}) value='{}' pos={} len={}", 
                 i, 
                 token.token_type, 
                 token.token_type.to_char(),
                 token.value_as_str(),
                 token.pos,
                 token.len);
    }
    
    println!("\n=== Final Results ===");
    println!("Token count: {}", state.tokens.len());
    println!("Fingerprint: '{}'", fingerprint.as_str());
    
    // Now let's manually step through tokenization to see what gets tokenized
    println!("\n=== Manual Tokenization Test ===");
    let mut tokenizer = SqliTokenizer::new(input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
    let mut token_count = 0;
    
    while let Some(token) = tokenizer.next_token() {
        println!("Raw token {}: type={:?} ({}) value='{}' pos={} len={}", 
                 token_count,
                 token.token_type,
                 token.token_type.to_char(),
                 token.value_as_str(),
                 token.pos,
                 token.len);
        token_count += 1;
        
        // Safety check to prevent infinite loops
        if token_count > 50 {
            println!("Breaking after 50 tokens to prevent infinite loop");
            break;
        }
    }
    
    println!("\nTotal raw tokens found: {}", token_count);
    
    // Check if semicolon is being tokenized at all
    let semicolon_pos = input.chars().position(|c| c == ';');
    if let Some(pos) = semicolon_pos {
        println!("Semicolon found at position {} in input", pos);
        
        // Look at what's around the semicolon
        let bytes = input.as_bytes();
        if pos > 0 {
            println!("Character before semicolon: '{}'", bytes[pos-1] as char);
        }
        if pos + 1 < bytes.len() {
            println!("Character after semicolon: '{}'", bytes[pos+1] as char);
        } else {
            println!("Semicolon is at end of input");
        }
    }
}