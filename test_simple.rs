use libinjectionrs::{detect_sqli, detect_xss};
use std::fs;
use std::path::Path;

fn main() {
    println!("Testing basic functionality...");
    
    // Test SQL injection detection
    let sqli_tests = [
        ("SELECT * FROM users WHERE id = 1", false, "Normal SQL should not be flagged"),
        ("1' OR '1'='1", true, "Classic SQL injection should be detected"),
        ("' UNION SELECT * FROM passwords --", true, "UNION attack should be detected"),
        ("Hello world", false, "Regular text should not be flagged"),
    ];
    
    println!("\n=== SQL Injection Tests ===");
    for (input, expected, description) in &sqli_tests {
        let result = detect_sqli(input.as_bytes());
        let is_sqli = result.is_injection();
        let status = if is_sqli == *expected { "✓" } else { "✗" };
        println!("{} {}: {} -> {} ({})", status, description, input, is_sqli, result.fingerprint());
    }
    
    // Test XSS detection
    let xss_tests = [
        ("<script>alert('xss')</script>", true, "Script tag should be detected"),
        ("<img src=x onerror=alert(1)>", true, "Event handler should be detected"),
        ("Hello <b>world</b>", false, "Safe HTML should not be flagged"),
        ("javascript:alert(1)", true, "Javascript protocol should be detected"),
    ];
    
    println!("\n=== XSS Tests ===");
    for (input, expected, description) in &xss_tests {
        let result = detect_xss(input.as_bytes());
        let is_xss = result.is_injection();
        let status = if is_xss == *expected { "✓" } else { "✗" };
        println!("{} {}: {} -> {}", status, description, input, is_xss);
    }
    
    // Test against a few files from testdata
    println!("\n=== Testing against sample files ===");
    let testdata_dir = Path::new("testdata");
    if testdata_dir.exists() {
        // Test a few SQL files
        if let Ok(entries) = fs::read_dir(testdata_dir) {
            let mut file_count = 0;
            for entry in entries {
                if file_count >= 3 { break; } // Test just a few files
                
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("txt") &&
                       path.file_name().unwrap().to_str().unwrap().starts_with("sqli-") {
                        
                        if let Ok(content) = fs::read_to_string(&path) {
                            let lines: Vec<&str> = content.lines().take(5).collect(); // First 5 lines only
                            
                            for line in lines {
                                if !line.trim().is_empty() {
                                    let result = detect_sqli(line.as_bytes());
                                    println!("File {}: {} -> {} ({})", 
                                            path.file_name().unwrap().to_str().unwrap(),
                                            line.chars().take(50).collect::<String>(),
                                            result.is_injection(),
                                            result.fingerprint());
                                }
                            }
                        }
                        file_count += 1;
                    }
                }
            }
        }
    } else {
        println!("testdata directory not found");
    }
    
    println!("\nBasic functionality test complete!");
}