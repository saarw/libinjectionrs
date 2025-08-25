use libinjectionrs::sqli::{SqliState, SqliFlags};

fn main() {
    let test_cases = [
        "1 OR 1 #",
        "1 OR 1 #a",
        "1 OR 1 # comment",
    ];
    
    for input in &test_cases {
        println!("\nTesting: '{}'", input);
        let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
        let fp = state.get_fingerprint();
        println!("  Fingerprint: '{}'", fp.as_str());
        
        // Get detection result
        let mut state2 = SqliState::new(input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
        let is_sqli = state2.detect();
        println!("  SQLi detected: {}", is_sqli);
    }
}