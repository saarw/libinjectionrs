// SQL injection blacklist checker - matches C implementation exactly

use super::sqli_data;

/// Check if a fingerprint is blacklisted
/// This matches libinjection_sqli_blacklist from the C version
pub fn is_blacklisted(fingerprint: &str) -> bool {
    // Match the C version: convert v0 fingerprint to v1 format
    // v0: up to 5 chars, mixed case  
    // v1: '0' prefix, up to 5 more chars, upper case
    
    if fingerprint.is_empty() {
        return false;
    }
    
    // Build the v1 fingerprint with '0' prefix and uppercase
    let mut fp2 = String::with_capacity(8);
    fp2.push('0');
    
    for ch in fingerprint.chars() {
        if ch >= 'a' && ch <= 'z' {
            // Convert to uppercase
            fp2.push((ch as u8 - 0x20) as char);
        } else {
            fp2.push(ch);
        }
    }
    
    // Check if this fingerprint exists in the keywords table with type 'F'
    sqli_data::lookup_word(&fp2) == crate::sqli::TokenType::Fingerprint
}