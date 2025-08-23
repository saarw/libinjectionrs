use libinjectionrs::detect_sqli;
use libinjectionrs::sqli::{SqliState, SqliFlags};

fn main() {
    let input = std::env::args().nth(1).unwrap_or_else(|| "admin'--".to_string());
    let input_bytes = input.as_bytes();
    
    println!("Input: {:?}", input);
    
    // Test different contexts like the C implementation
    let contexts = [
        ("NONE+ANSI", SqliFlags::NONE | SqliFlags::ANSI),
        ("NONE+MYSQL", SqliFlags::NONE | SqliFlags::MYSQL), 
        ("SINGLE+ANSI", SqliFlags::QUOTE_SINGLE | SqliFlags::ANSI),
        ("SINGLE+MYSQL", SqliFlags::QUOTE_SINGLE | SqliFlags::MYSQL),
        ("DOUBLE+MYSQL", SqliFlags::QUOTE_DOUBLE | SqliFlags::MYSQL),
    ];
    
    for (name, flags) in contexts {
        println!("\n=== Testing context: {} ===", name);
        
        let quoted_input_single;
        let quoted_input_double;
        let input_to_use = if flags.contains(SqliFlags::QUOTE_SINGLE) {
            // Prepend single quote like C implementation
            quoted_input_single = {
                let mut v = Vec::with_capacity(input_bytes.len() + 1);
                v.push(b'\'');
                v.extend_from_slice(input_bytes);
                v
            };
            &quoted_input_single
        } else if flags.contains(SqliFlags::QUOTE_DOUBLE) {
            // Prepend double quote
            quoted_input_double = {
                let mut v = Vec::with_capacity(input_bytes.len() + 1);
                v.push(b'\"');
                v.extend_from_slice(input_bytes);
                v
            };
            &quoted_input_double
        } else {
            input_bytes
        };
        
        let mut state = SqliState::new(input_to_use, flags);
        
        state.tokenize();
        
        println!("Tokens before folding ({}):", state.tokens.len());
        for (i, token) in state.tokens.iter().enumerate() {
            let value = std::str::from_utf8(token.value_slice()).unwrap_or("???");
            println!("  {}: {:?} = {:?}", i, token.token_type, value);
        }
        
        state.fold();
        
        println!("Tokens after folding ({}):", state.tokens.len());
        for (i, token) in state.tokens.iter().enumerate() {
            let value = std::str::from_utf8(token.value_slice()).unwrap_or("???");
            println!("  {}: {:?} = {:?}", i, token.token_type, value);
        }
        
        let fingerprint_chars: Vec<char> = state.tokens.iter()
            .map(|t| t.token_type.to_char())
            .collect();
        let fingerprint: String = fingerprint_chars.iter().collect();
        
        println!("Fingerprint: {:?}", fingerprint);
        
        let is_sqli = state.check_fingerprint();
        println!("Is SQLi: {}", is_sqli);
    }
    
    // Test with main API
    println!("\n=== Main API Result ===");
    let result = detect_sqli(input_bytes);
    println!("Result: {:?}", result);
}