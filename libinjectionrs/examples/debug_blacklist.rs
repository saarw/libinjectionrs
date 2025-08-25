use libinjectionrs::sqli::{blacklist, SqliDetector, SqliFlags};

fn main() {
    let fingerprints = ["1&1", "1&1c", "1&1on"];
    
    for fp in fingerprints.iter() {
        let is_bl = blacklist::is_blacklisted(fp);
        println!("{}: blacklisted = {}", fp, is_bl);
    }
    
    // Test the actual detection
    let input = "1 OR 1 # comment";
    let detector = SqliDetector::new();
    let result = detector.detect(input.as_bytes());
    println!("Detection result: {:?}", result);
    
    // Test ANSI explicitly
    let detector = SqliDetector::new().with_flags(SqliFlags::QUOTE_NONE | SqliFlags::SQL_ANSI);
    let result = detector.detect(input.as_bytes());
    println!("ANSI result: {:?}", result);
}