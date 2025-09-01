use libinjectionrs::{detect_sqli, detect_xss};

fn main() {
    println!("Testing libinjectionrs functionality...");
    
    // Test SQL injection detection
    let sqli_tests = [
        ("SELECT * FROM users WHERE id = 1", "Normal SQL"),
        ("1' OR '1'='1", "SQL injection attempt"),
        ("' UNION SELECT * FROM passwords --", "UNION attack"),
        ("Hello world", "Regular text"),
    ];
    
    println!("\n=== SQL Injection Detection ===");
    for (input, description) in &sqli_tests {
        let result = detect_sqli(input.as_bytes());
        let fingerprint_str = result.fingerprint
            .map(|fp| fp.to_string())
            .unwrap_or_else(|| "none".to_string());
        println!("{}: {} -> {} (fingerprint: {})", 
                description, input, result.is_injection, fingerprint_str);
    }
    
    // Test XSS detection  
    let xss_tests = [
        ("<script>alert('xss')</script>", "Script tag"),
        ("<img src=x onerror=alert(1)>", "Event handler"),
        ("Hello <b>world</b>", "Safe HTML"),
        ("javascript:alert(1)", "Javascript protocol"),
    ];
    
    println!("\n=== XSS Detection ===");
    for (input, description) in &xss_tests {
        let result = detect_xss(input.as_bytes());
        println!("{}: {} -> {}", description, input, result.is_injection());
    }
}