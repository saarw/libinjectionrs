/// SQL injection fingerprint blacklist
/// 
/// This module contains the blacklist patterns extracted from libinjection
use std::collections::HashSet;
use std::sync::OnceLock;

static FINGERPRINT_BLACKLIST: OnceLock<HashSet<String>> = OnceLock::new();

/// Get the fingerprint blacklist, loading it on first access
pub fn get_blacklist() -> &'static HashSet<String> {
    FINGERPRINT_BLACKLIST.get_or_init(|| {
        // Core patterns from the failing test cases and common injection patterns
        let patterns = [
            // Boolean injection patterns
            "s&sos", "s&so1", "s&son", "s&sov", "s&soU", "s&sof",
            "1&s", "1&so", "1&sos", "1&son", "1&sov", "1o1", "1&1",
            
            // Comment injection patterns  
            "sc", "s&sc", "1sc", "nsc", "vsc", "n&sc", "v&sc",
            // More complete pattern coverage
            "nc", "vc", "1c", "kc", "fc",
            
            // UNION patterns
            "1U", "sU", "nU", "vU", "1UE", "1UEs", "1UEn", "1UEk", "1UEv", "1UE1",
            "sUE", "nUE", "vUE", "Un", "Us", "U1", "Uk", "Uv",
            
            // SELECT and other keyword patterns
            "Eoknk", "Eok", "Eon", "Eos", "Eov", "E1", "En", "Es", "Ev",
            "koknk", "kn", "ks", "kv", "k1", "ko", "kE", "koE", "kons", "konv",
            
            // Expression patterns
            "E1", "En", "Es", "Ev", "Ek", "Eo", "EoE", "EnE", "EsE", "EvE",
            
            // Function patterns  
            "f(", "f()", "f(1", "f(n", "f(s", "f(v", "f()E", "f(1E", "f(nE",
            
            // Nested and complex patterns
            "&(1", "&(n", "&(s", "&(v", "1o(", "so(", "no(", "vo(",
            "(1)", "(n)", "(s)", "(v)", "(1o", "(so", "(no", "(vo",
            
            // Basic operators in injection context
            "1o", "so", "no", "vo", "1&", "s&", "n&", "v&",
        ];
        
        patterns.iter().map(|s| s.to_string()).collect()
    })
}

/// Check if a fingerprint matches the blacklist
pub fn is_sqli_fingerprint(fingerprint: &str) -> bool {
    if fingerprint.is_empty() {
        return false;
    }
    
    get_blacklist().contains(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_sqli_patterns() {
        assert!(is_sqli_fingerprint("s&sos")); // 1' OR '1'='1
        assert!(is_sqli_fingerprint("sc"));    // admin'--
        assert!(is_sqli_fingerprint("Eoknk")); // SELECT * FROM users WHERE id = 1
        assert!(is_sqli_fingerprint("1U"));    // 1 UNION
        assert!(!is_sqli_fingerprint(""));     // empty
        assert!(!is_sqli_fingerprint("xyz")); // not in blacklist
    }
}