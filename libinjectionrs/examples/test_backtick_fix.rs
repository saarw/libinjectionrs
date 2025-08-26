use libinjectionrs::{SqliState, SqliFlags};

fn main() {
    let test_input = "@z)`";
    println!("Testing input: {:?}", test_input);
    
    let mut state = SqliState::new(test_input.as_bytes(), SqliFlags::FLAG_SQL_ANSI);
    let is_sqli = state.detect();
    
    println!("Result: {}", is_sqli);
    if is_sqli {
        let fingerprint = state.get_fingerprint();
        println!("Fingerprint: {:?}", fingerprint.as_str());
    } else {
        println!("No fingerprint (not detected as SQL injection)");
    }
}