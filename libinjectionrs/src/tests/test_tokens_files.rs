#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::disallowed_methods)]
#![allow(clippy::panic)]

use std::fs;
use std::path::Path;
use crate::sqli::{SqliFlags, SqliTokenizer, Token, TokenType};

#[derive(Debug)]
struct TestCase {
    name: String,
    input: Vec<u8>,  // Changed to Vec<u8> to preserve raw bytes
    expected: String,
}

fn parse_test_file(raw_bytes: &[u8]) -> Option<TestCase> {
    // Parse the file preserving raw bytes for the input section
    let mut state = 0; // 0=looking for --TEST--, 1=reading test name, 2=reading input, 3=reading expected
    let mut test_name = String::new();
    let mut input_bytes = Vec::new();
    let mut expected = String::new();
    let mut line_start = 0;
    let mut first_input_line = true;
    
    // Process line by line, but keep raw bytes for input section
    for (i, &byte) in raw_bytes.iter().enumerate() {
        if byte == b'\n' || i == raw_bytes.len() - 1 {
            let line_end = if byte == b'\n' { i } else { i + 1 };
            let line_bytes = &raw_bytes[line_start..line_end];
            
            // Convert line to string for parsing structure (except for input content)
            let line_str = if state == 2 {
                // For input section, we'll handle this separately
                String::new()
            } else {
                String::from_utf8_lossy(line_bytes).trim_end().to_string()
            };
            
            match state {
                0 => {
                    if line_str == "--TEST--" {
                        state = 1;
                    }
                }
                1 => {
                    if line_str == "--INPUT--" {
                        state = 2;
                        first_input_line = true;
                    } else if !line_str.is_empty() {
                        test_name.push_str(&line_str);
                    }
                }
                2 => {
                    let line_str = String::from_utf8_lossy(line_bytes).to_string();
                    if line_str.trim() == "--EXPECTED--" {
                        state = 3;
                    } else {
                        // Add raw bytes to input, preserving original bytes including invalid UTF-8
                        if !first_input_line {
                            input_bytes.push(b'\n');
                        }
                        first_input_line = false;
                        
                        // Add the line bytes directly (without the newline, we'll add it above)
                        input_bytes.extend_from_slice(line_bytes);
                    }
                }
                3 => {
                    if !line_str.is_empty() {
                        if !expected.is_empty() {
                            expected.push('\n');
                        }
                        expected.push_str(&line_str);
                    }
                }
                _ => {}
            }
            
            line_start = i + 1;
        }
    }

    if state == 3 {
        Some(TestCase {
            name: test_name,
            input: input_bytes,
            expected,
        })
    } else {
        None
    }
}

fn token_type_to_char(token_type: TokenType) -> char {
    token_type.to_char()
}

fn format_token(token: &Token) -> String {
    let type_char = token_type_to_char(token.token_type);
    let value = format_token_value(token);
    
    // Format as: "type_char value" but avoid trailing space for empty values
    if value.is_empty() {
        format!("{}", type_char)
    } else {
        format!("{} {}", type_char, value)
    }
}

fn format_token_value(token: &Token) -> String {
    match token.token_type {
        TokenType::String => format_string_token(token),
        TokenType::Variable => format_variable_token(token),
        _ => token.value_as_str().to_string(),
    }
}

// Equivalent to C print_string() function
fn format_string_token(token: &Token) -> String {
    let mut result = String::new();
    
    // Add opening quote if present
    if token.str_open != 0 {
        result.push(token.str_open as char);
    }
    
    // Add content
    result.push_str(token.value_as_str());
    
    // Add closing quote if present  
    if token.str_close != 0 {
        result.push(token.str_close as char);
    }
    
    result
}

// Equivalent to C print_var() function
fn format_variable_token(token: &Token) -> String {
    let mut result = String::new();
    
    // Check if this is a complex variable (has quotes/backticks)
    if token.str_open != 0 {
        // Complex case: @@`version` -> count=2, value="version", str_open='`'
        // Need to reconstruct: @@ + ` + value + `
        
        // Add @ symbols based on count
        for _ in 0..token.count {
            result.push('@');
        }
        
        // Add opening quote/backtick
        result.push(token.str_open as char);
        
        // Add the content (variable name or string content)
        result.push_str(token.value_as_str());
        
        // Add closing quote/backtick if present
        if token.str_close != 0 {
            result.push(token.str_close as char);
        }
    } else {
        // Simple case: @var -> value="@var" (includes @ symbols already)
        result.push_str(token.value_as_str());
    }
    
    result
}

fn run_sqli_tokenization(input: &[u8]) -> String {
    let flags = SqliFlags::FLAG_SQL_ANSI;
    let mut tokenizer = SqliTokenizer::new(input, flags);
    let mut result = Vec::new();

    while let Some(token) = tokenizer.next_token() {
        result.push(format_token(&token));
    }

    result.join("\n")
}

fn run_single_tokens_test(file_path: &Path) -> Result<(), String> {
    // Read raw bytes to match C behavior which doesn't validate UTF-8
    let bytes = fs::read(file_path)
        .map_err(|e| format!("Failed to read file {:?}: {}", file_path, e))?;

    let test_case = parse_test_file(&bytes)
        .ok_or_else(|| format!("Failed to parse test file {:?}", file_path))?;

    let actual = run_sqli_tokenization(&test_case.input);

    if actual != test_case.expected {
        let input_display = String::from_utf8_lossy(&test_case.input);
        return Err(format!(
            "Test failed for {:?}\nTest: {}\nInput: {:?} (bytes: {:?})\nExpected:\n{}\nActual:\n{}",
            file_path, test_case.name, input_display, test_case.input, test_case.expected, actual
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_all_tokens_files() {
        let test_dir = "../libinjection-c/tests";
        
        // Check if test directory exists
        if !Path::new(test_dir).exists() {
            panic!("Test directory {} does not exist. Make sure libinjection-c submodule is initialized.", test_dir);
        }

        let entries = fs::read_dir(test_dir).expect("Failed to read test directory");
        let mut test_files = Vec::new();
        let mut failures = Vec::new();

        for entry in entries {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with("test-tokens-") && filename.ends_with(".txt") {
                    test_files.push(path);
                }
            }
        }

        test_files.sort();
        
        println!("Found {} tokens test files", test_files.len());

        for test_file in &test_files {
            match run_single_tokens_test(test_file) {
                Ok(()) => {
                    println!("✓ {:?}", test_file.file_name().unwrap());
                }
                Err(e) => {
                    println!("✗ {:?}: {}", test_file.file_name().unwrap(), e);
                    failures.push(format!("{}: {}", test_file.display(), e));
                }
            }
        }

        if !failures.is_empty() {
            println!("\n{} test(s) failed:", failures.len());
            for failure in &failures[..std::cmp::min(5, failures.len())] {
                println!("  {}", failure);
            }
            if failures.len() > 5 {
                println!("  ... and {} more", failures.len() - 5);
            }
            panic!("{} tokens test(s) failed", failures.len());
        }

        println!("All {} tokens tests passed!", test_files.len());
    }

    #[test]
    fn test_single_tokens_example() {
        // Test a simple case first based on test-tokens-numbers-string-001.txt
        let input = "SELECT x'1234';";
        let expected = "E SELECT\n1 x'1234'\n; ;";
        let actual = run_sqli_tokenization(input.as_bytes());
        
        // For debugging, let's print the actual result first
        println!("Input: {}", input);
        println!("Expected:\n{}", expected);
        println!("Actual:\n{}", actual);
        
        assert_eq!(actual, expected, "Simple tokens tokenization test failed");
    }

    #[test]
    fn test_backquote_variable_debug() {
        // Debug the failing case from test-tokens-backquotes-008.txt
        let input = "SELECT @`foo``bar`;";
        println!("Input: {}", input);
        
        let input_bytes = input.as_bytes();
        let flags = SqliFlags::FLAG_SQL_ANSI;
        let mut tokenizer = SqliTokenizer::new(input_bytes, flags);
        
        println!("Tokens:");
        while let Some(token) = tokenizer.next_token() {
            println!("  Type: {:?} ({}), Value: {:?}, Pos: {}, Len: {}", 
                     token.token_type, token_type_to_char(token.token_type), 
                     token.value_as_str(), token.pos, token.len);
        }
        
        let expected = "E SELECT\nv @`foo``bar`\n; ;";
        let actual = run_sqli_tokenization(input.as_bytes());
        
        println!("Expected:\n{}", expected);
        println!("Actual:\n{}", actual);
        
        // Don't assert yet, just show the difference
    }

    #[test]
    fn test_b_string_debug() {
        // Debug the failing case from test-tokens-numbers-string-009.txt
        let input = "SELECT b'";
        println!("Input: {}", input);
        
        let input_bytes = input.as_bytes();
        let flags = SqliFlags::FLAG_SQL_ANSI;
        let mut tokenizer = SqliTokenizer::new(input_bytes, flags);
        
        println!("Tokens:");
        let mut token_count = 0;
        while let Some(token) = tokenizer.next_token() {
            token_count += 1;
            println!("  {}: Type: {:?} ({}), Value: {:?}, Pos: {}, Len: {}, str_open: {}, str_close: {}", 
                     token_count, token.token_type, token_type_to_char(token.token_type), 
                     token.value_as_str(), token.pos, token.len, token.str_open, token.str_close);
        }
        println!("  Total tokens: {}, Input length: {}", token_count, input.len());
        
        let expected = "E SELECT\nn b\ns '";
        let actual = run_sqli_tokenization(input.as_bytes());
        
        println!("Expected:\n{}", expected);
        println!("Actual:\n{}", actual);
        
        // Don't assert yet, just show the difference
    }

    #[test]
    fn test_utf8_fix_verification() {
        // Verify that our UTF-8 fix works correctly
        let input = "SELECT テスト;";
        println!("\n=== UTF-8 Fix Verification ===");
        println!("Testing: {}", input);
        println!("UTF-8 bytes: {:?}", input.as_bytes());
        
        let expected = "E SELECT\nn テスト\n; ;";
        let actual = run_sqli_tokenization(input.as_bytes());
        
        println!("Expected:\n{}", expected);
        println!("Actual:\n{}", actual);
        
        // This should now pass with our fix
        assert_eq!(actual, expected, "UTF-8 tokenization should match C behavior");
    }


}