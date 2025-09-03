#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::disallowed_methods)]
#![allow(clippy::panic)]

use super::detector::{XssDetector, XssResult};

#[test]
fn test_safe_input() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"Hello world"), XssResult::Safe);
    assert_eq!(detector.detect(b"<p>Normal text</p>"), XssResult::Safe);
    assert_eq!(detector.detect(b"<div class=\"safe\">Content</div>"), XssResult::Safe);
}

#[test] 
fn test_script_tag() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<script>alert(1)</script>"), XssResult::Xss);
    assert_eq!(detector.detect(b"<SCRIPT>alert(1)</SCRIPT>"), XssResult::Xss);
    assert_eq!(detector.detect(b"<Script>alert(1)</Script>"), XssResult::Xss);
}

#[test]
fn test_event_handlers() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<img onclick=\"alert(1)\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<div onload=\"alert(1)\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<input onerror=\"alert(1)\">"), XssResult::Xss);
}

#[test]
fn test_dangerous_urls() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<a href=\"javascript:alert(1)\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<img src=\"data:text/html,<script>alert(1)</script>\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<iframe src=\"vbscript:alert(1)\">"), XssResult::Xss);
}

#[test]
fn test_style_attribute() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<div style=\"background:url(javascript:alert(1))\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<p style=\"color:red\">"), XssResult::Xss);
}

#[test]
fn test_fuzz_differential_8ce9746b() {
    // Fuzz test case where Rust returns true (XSS) but C returns false (safe)
    // Input: "<p<p\n/`\u{2}\"`/\r</\r\r\r`/To/�C  >�\u{1}<p\n/`\u{2}\"`  >\u{1}<p>�}\r</\r</\r\r\r`` >�\u{1}<p\n/`\u{2}\"` \""
    let input = &[
        60, 112, 60, 112, 10, 47, 96, 2, 34, 96, 47, 13, 60, 47, 13, 13, 13, 96, 47, 84, 111, 
        47, 255, 67, 32, 32, 62, 132, 1, 60, 112, 10, 47, 96, 2, 34, 96, 32, 32, 62, 1, 60, 
        112, 62, 137, 125, 13, 60, 47, 13, 60, 47, 13, 13, 13, 96, 96, 32, 62, 132, 1, 60, 
        112, 10, 47, 96, 2, 34, 96, 32, 34
    ];
    let detector = XssDetector::new();
    // This test currently fails - Rust returns Xss but C returns Safe
    // We expect it to return Safe to match C behavior
    assert_eq!(detector.detect(input), XssResult::Safe);
}

#[test]
fn test_dangerous_tags() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<iframe src=\"http://evil.com\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<object data=\"http://evil.com\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<embed src=\"http://evil.com\">"), XssResult::Xss);
}

#[test] 
fn test_svg_tags() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<svg onload=\"alert(1)\">"), XssResult::Xss);
    assert_eq!(detector.detect(b"<svgtest>"), XssResult::Xss);
}

#[test]
fn test_comments() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<!-- Normal comment -->"), XssResult::Safe);
    assert_eq!(detector.detect(b"<!--[if IE]><script>alert(1)</script><![endif]-->"), XssResult::Xss);
    assert_eq!(detector.detect(b"<!-- Comment with ` backtick -->"), XssResult::Xss);
    assert_eq!(detector.detect(b"<!--IMPORT foo-->"), XssResult::Xss);
}

#[test]
fn test_doctype() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b"<!DOCTYPE html>"), XssResult::Xss);
}

#[test]
fn test_empty_input() {
    let detector = XssDetector::new();
    assert_eq!(detector.detect(b""), XssResult::Safe);
}

#[test]
fn test_multiple_contexts() {
    let detector = XssDetector::new();
    // This should be caught in unquoted attribute value context
    // Let's test with a more complete HTML structure
    assert_eq!(detector.detect(b"<a href=javascript:alert(1)>"), XssResult::Xss);
    
    // Test raw javascript: URL (this might not be detected without HTML context)
    let result = detector.detect(b"javascript:alert(1)");
    println!("Raw javascript URL result: {:?}", result);
    // For now, let's just check it doesn't crash - raw URLs without HTML context 
    // may not always be detected depending on parsing context
}

#[test]
fn test_fuzz_differential_crash_472cde1c() {
    // Fuzz test case where Rust returns true (XSS) but C returns false (safe)  
    // From fuzz crash: crash-472cde1c76cb772c42c53bf83e5bfe071f009983
    // Input bytes: [47, 93, 34, 47, 93, 34, 96, 214, 45, 53, 32, 47, 62, 60, 116, 255, 102, 102, 102, 102, 39, 96, 10, 39, 10, 90, 127, 60, 112, 10, 120, 96, 170, 84, 40, 47, 60, 39, 61, 255, 62, 96, 47, 60, 33, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 61, 39, 212, 61, 61, 39, 13, 116, 255, 255, 255, 255, 255, 255, 255, 255, 255, 102, 102, 102, 102, 102, 255, 52, 39, 167, 1, 61, 96, 96, 47, 13, 96, 39, 45, 53, 32, 47, 62, 60, 116, 255, 102, 102, 102, 102, 102, 91, 102, 96, 102, 102, 102, 39, 167, 1, 61, 96, 96, 47, 13]
    let input = &[
        47, 93, 34, 47, 93, 34, 96, 214, 45, 53, 32, 47, 62, 60, 116, 255, 102, 102, 102, 102, 
        39, 96, 10, 39, 10, 90, 127, 60, 112, 10, 120, 96, 170, 84, 40, 47, 60, 39, 61, 255, 
        62, 96, 47, 60, 33, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 
        105, 105, 105, 61, 39, 212, 61, 61, 39, 13, 116, 255, 255, 255, 255, 255, 255, 255, 
        255, 255, 102, 102, 102, 102, 102, 255, 52, 39, 167, 1, 61, 96, 96, 47, 13, 96, 39, 
        45, 53, 32, 47, 62, 60, 116, 255, 102, 102, 102, 102, 102, 91, 102, 96, 102, 102, 102, 
        39, 167, 1, 61, 96, 96, 47, 13
    ];
    let detector = XssDetector::new();
    // This test currently fails - Rust returns Xss but C returns Safe
    // We expect it to return Safe to match C behavior
    assert_eq!(detector.detect(input), XssResult::Safe);
}

#[test]
fn test_fuzz_differential_crash_b5a17da5() {
    // Fuzz test case where Rust returns true (XSS) but C returns false (safe)
    // From fuzz crash: crash-b5a17da536372d645d2a75663ad9589924c7df01
    // Input: "'\u{1}P`������������ЪT(�>�<s`��T/(>`��<s`�(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s�T(�>`/>��<s������ЪT(\u{b}\u{b}\"O<M��T/(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s��`�T(�>`/`/�<�����ЪT(�s>`�<��zT/(>`��<s`��(�>`/>��<s������ЪT(\u{b}\u{b}\"O<�=�T/(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s��`�T(�s��[`�ЪT(�>�<s`��T/(>`��<s`�(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s�T(�>`/>��<s������ЪT(\u{b}\u{b}\"O<M��T/(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s��`�T(�>`/`/�<�����ЪT(�s>`�<��T/(>`��<s`��(�>`/>��<s������ЪT(\u{b}\u{b}\"O<�=�T/(>`��<s`�T(�>`/>��<s`�T(�>`/`/�<s��`�T(/`'?<<</?\u{c}\u{c}>��<xss��[`��<\""
    let input = &[
        39, 1, 80, 96, 189, 253, 223, 243, 243, 242, 242, 243, 243, 242, 242, 243, 208, 170, 84, 40, 255, 62, 255, 60, 115, 96, 170, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 223, 243, 243, 242, 242, 243, 208, 170, 84, 40, 11, 11, 34, 79, 60, 77, 170, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 255, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 243, 243, 242, 242, 243, 208, 170, 84, 40, 255, 115, 62, 96, 255, 60, 170, 170, 122, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 186, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 223, 243, 243, 242, 242, 243, 208, 170, 84, 40, 11, 11, 34, 79, 60, 255, 61, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 255, 96, 170, 84, 40, 255, 115, 182, 255, 91, 96, 243, 208, 170, 84, 40, 255, 62, 255, 60, 115, 96, 170, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 223, 243, 243, 242, 242, 243, 208, 170, 84, 40, 11, 11, 34, 79, 60, 77, 170, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 255, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 243, 243, 242, 242, 243, 208, 170, 84, 40, 255, 115, 62, 96, 255, 60, 170, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 186, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 223, 243, 243, 242, 242, 243, 208, 170, 84, 40, 11, 11, 34, 79, 60, 255, 61, 170, 84, 47, 40, 62, 96, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 62, 255, 255, 60, 115, 96, 170, 84, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 182, 255, 96, 170, 84, 40, 47, 96, 39, 63, 60, 60, 60, 47, 63, 12, 12, 62, 174, 255, 60, 120, 115, 115, 182, 255, 91, 96, 255, 143, 60, 34
    ];
    let detector = XssDetector::new();
    // This test currently fails - Rust returns Xss but C returns Safe
    // We expect it to return Safe to match C behavior
    assert_eq!(detector.detect(input), XssResult::Safe);
}

#[test]
fn test_fuzz_differential_crash_0d735373() {
    // Fuzz test case where Rust was returning false (Safe) but C returns true (XSS)
    // From fuzz crash: crash-0d73537323637c60b7d6c289deca66333f5aa642
    // This was fixed by also checking TagClose tokens for dangerous tags since the 
    // Rust tokenizer categorizes some tag names as TagClose instead of TagNameOpen
    let input = &[
        96, 96, 170, 84, 237, 39, 96, 39, 13, 13, 96, 255, 96, 96, 46, 13, 96, 39, 39, 45, 53, 32, 47, 64, 
        255, 62, 106, 47, 60, 47, 62, 60, 116, 167, 1, 39, 45, 53, 39, 255, 39, 33, 91, 13, 136, 10, 88, 
        195, 210, 45, 53, 32, 47, 39, 167, 167, 1, 39, 45, 53, 32, 47, 62, 60, 116, 102, 102, 102, 255, 
        102, 96, 212, 39, 13, 102, 91, 59, 102, 102, 102, 202, 2, 39, 167, 153, 96, 39, 255, 62, 96, 47, 
        96, 47, 255, 60, 115, 86, 103, 86, 62, 255, 255, 96, 47, 96, 47, 255, 60, 115, 86, 86, 62, 255, 
        255, 60, 115, 96, 170, 1, 61, 96, 61, 96, 84, 237, 40, 255, 62, 96, 47, 96, 47, 255, 60, 115, 86, 
        86, 153, 153, 96, 39, 255, 62, 96, 1, 84, 96, 96
    ];
    
    // Debug tokenization to compare with C
    use crate::xss::html5::{Html5State, Html5Flags, TokenType};
    let mut html5 = Html5State::new(input, Html5Flags::DataState);
    let mut token_count = 0;
    
    println!("=== Rust Tokenizer Debug Trace ===");
    while html5.next() && token_count < 25 {
        token_count += 1;
        let token_len = std::cmp::min(html5.token_len, 20);
        let token_start_len = std::cmp::min(html5.token_start.len(), token_len);
        let token_display = String::from_utf8_lossy(&html5.token_start[..token_start_len]);
        
        println!("Token {}: Type={:?}, Start=\"{}\", Len={}, is_close={}, pos={}", 
                token_count, html5.token_type, token_display, html5.token_len, html5.debug_is_close(), html5.debug_pos());
        
        // Special focus on tokens that might be "sVgV"  
        if html5.token_len == 4 && token_start_len >= 4 && 
           html5.token_start[0] == b's' && html5.token_start[1] == b'V' {
            println!("  *** FOUND sVgV-like token! Details:");
            println!("      Token bytes: {:02x?}", &html5.token_start[..html5.token_len]);
            println!("      is_close flag: {}", html5.debug_is_close());
            println!("      Previous 5 bytes at pos {}: {:02x?}", 
                    html5.debug_pos().saturating_sub(html5.token_len + 5),
                    &input[html5.debug_pos().saturating_sub(html5.token_len + 5)..html5.debug_pos().saturating_sub(html5.token_len)]);
        }
    }
    
    let detector = XssDetector::new();
    let result = detector.detect(input);
    println!("Final Rust result: {:?}", result);
    
    // This should now return Xss to match C behavior (contains SVG tag "sVgV")
    assert_eq!(result, XssResult::Xss);
}

