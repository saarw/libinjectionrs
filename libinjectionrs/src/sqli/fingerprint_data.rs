/// Compiled fingerprint data matching C implementation
/// 
/// This module contains the exact fingerprints from the C implementation
/// in v1 format (0-prefixed, uppercase) for binary search matching

use std::collections::HashSet;
use std::sync::OnceLock;

static FINGERPRINT_SET: OnceLock<HashSet<String>> = OnceLock::new();

/// Get the compiled fingerprint set
pub fn get_fingerprint_set() -> &'static HashSet<String> {
    FINGERPRINT_SET.get_or_init(|| {
        // Extract the fingerprints from the C implementation and convert them
        // This should match exactly what's in libinjection_sqli_data.h
        let raw_fingerprints = include_str!("../../../libinjection-c/src/fingerprints.txt");
        
        raw_fingerprints
            .lines()
            .map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return String::new();
                }
                // Convert to v1 format: prepend '0' and convert to uppercase
                format!("0{}", line.to_uppercase())
            })
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Check if a v1 format fingerprint is in the compiled set
/// This matches the C implementation's is_keyword(...) == TYPE_FINGERPRINT check
pub fn is_fingerprint_match(v1_fingerprint: &str) -> bool {
    get_fingerprint_set().contains(v1_fingerprint)
}

/// Convert a raw fingerprint to v1 format (like C implementation)
pub fn to_v1_format(fingerprint: &str) -> String {
    if fingerprint.is_empty() {
        return String::new();
    }
    
    // Match C logic: prepend '0' and convert to uppercase
    format!("0{}", fingerprint.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_format_conversion() {
        assert_eq!(to_v1_format("s&sos"), "0S&SOS");
        assert_eq!(to_v1_format("sc"), "0SC");
        assert_eq!(to_v1_format("Eoknk"), "0EOKNK");
        assert_eq!(to_v1_format(""), "");
    }

    #[test]
    fn test_known_fingerprints() {
        // These should match the C implementation
        assert!(is_fingerprint_match("0S&SOS")); // 1' OR '1'='1
        assert!(is_fingerprint_match("0SC"));    // admin'--
        assert!(is_fingerprint_match("0EOKNK")); // SELECT * FROM users WHERE id = 1
    }

    #[test]
    fn test_unknown_fingerprints() {
        assert!(!is_fingerprint_match("0INVALID"));
        assert!(!is_fingerprint_match("NOTFOUND"));
        assert!(!is_fingerprint_match(""));
    }
}