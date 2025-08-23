use libinjectionrs::{detect_sqli, detect_xss};

fn main() {
    println!("Testing against sample corpus entries...");
    
    // Sample SQL injection payloads from corpus
    let sqli_samples = [
        "SO_BUY AND IF(1=1,BENCHMARK(1589466,MD5(0X41)),0)",  // Decoded from corpus
        "SO_BUY; IF (1=1) WAITFOR DELAY '00:00:01'--",        // Time-based attack
        "select 1 from foo where",                             // Basic query
        "select @version from foo where",                      // Version extraction
        "PHPX AND CHAR(124) USER CHAR(124)=0 AND XX=X",       // Character injection
        "' UNION SELECT 1,2,3--",                             // Union attack
        "1' OR 1=1--",                                         // Classic injection
    ];
    
    println!("\n=== SQL Injection Detection ===");
    for (i, payload) in sqli_samples.iter().enumerate() {
        let result = detect_sqli(payload.as_bytes());
        let fingerprint_str = result.fingerprint()
            .map(|fp| fp.to_string())
            .unwrap_or_else(|| "none".to_string());
        
        let status = if result.is_injection() { "🔴 DETECTED" } else { "🟢 CLEAN" };
        println!("{}: {} -> {} (fingerprint: {})", 
                i+1, status, payload, fingerprint_str);
    }
    
    // Sample XSS payloads
    let xss_samples = [
        "<script>alert(1);</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert('xss')",
        "<svg onload=alert(1)>",
        "onclick=alert(1)",
        "<iframe src=javascript:alert(1)></iframe>",
    ];
    
    println!("\n=== XSS Detection ===");
    for (i, payload) in xss_samples.iter().enumerate() {
        let result = detect_xss(payload.as_bytes());
        let status = if result.is_injection() { "🔴 DETECTED" } else { "🟢 CLEAN" };
        println!("{}: {} -> {}", i+1, status, payload);
    }
    
    // Test against some normal content
    let normal_samples = [
        "Hello world",
        "SELECT * FROM users WHERE id = 1",
        "<div>Hello <b>world</b></div>",
        "This is a normal string",
        "username=admin&password=secret",
    ];
    
    println!("\n=== Normal Content (Should be Clean) ===");
    for (i, content) in normal_samples.iter().enumerate() {
        let sqli_result = detect_sqli(content.as_bytes());
        let xss_result = detect_xss(content.as_bytes());
        
        let sqli_status = if sqli_result.is_injection() { "🔴 SQLI" } else { "🟢 OK" };
        let xss_status = if xss_result.is_injection() { "🔴 XSS" } else { "🟢 OK" };
        
        println!("{}: {} | {} -> {}", i+1, sqli_status, xss_status, content);
    }
}