#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::disallowed_methods)]
#![allow(clippy::panic)]

use crate::sqli::*;
use std::fs;
use std::path::Path;

/// Format token value like C's testdriver - reconstructs variable prefixes and string quotes
fn format_token_for_c_compatibility(token: &Token) -> String {
    match token.token_type {
        TokenType::Variable => {
            // Rust tokenizer already includes @ symbols in the token value, unlike C
            // C stores variable name without @ and adds them in print_var based on count
            // Rust stores the full @variable string, so just return it as-is
            token.value_as_str().to_string()
        }
        TokenType::String => {
            // Reconstruct string quotes like C's print_string function
            let mut result = String::new();
            if token.str_open != 0 {
                result.push(token.str_open as char);
            }
            result.push_str(token.value_as_str());
            if token.str_close != 0 {
                result.push(token.str_close as char);
            }
            result
        }
        _ => token.value_as_str().to_string()
    }
}

/// Test all folding test cases from the C library
#[test]
fn test_folding_from_c_testdata() {
    let test_dir = Path::new("../libinjection-c/tests");
    if !test_dir.exists() {
        panic!("C test directory not found at ../libinjection-c/tests");
    }

    let mut test_files = Vec::new();
    for entry in fs::read_dir(test_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if let Some(filename) = path.file_name() {
            if filename.to_str().unwrap().starts_with("test-folding-") {
                test_files.push(path);
            }
        }
    }

    test_files.sort();
    println!("Found {} folding test files", test_files.len());

    let mut passed = 0;
    let mut failed = 0;

    for test_file in test_files {
        let content = fs::read_to_string(&test_file).unwrap();
        let test_case = parse_test_file(&content);
        
        if let Some((test_name, input, expected)) = test_case {
            let result = run_folding_test(&input, &expected);
            if result {
                passed += 1;
                println!("PASS: {} - {}", test_file.file_name().unwrap().to_str().unwrap(), test_name);
            } else {
                failed += 1;
                println!("FAIL: {} - {}", test_file.file_name().unwrap().to_str().unwrap(), test_name);
                
                // Show the actual vs expected for debugging
                let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_NONE);
                let token_count = state.fold_tokens();
                let expected_lines: Vec<&str> = expected.lines().collect();
                
                println!("  Input: {}", input);
                println!("  Expected tokens:");
                for line in expected.lines() {
                    println!("    {}", line);
                }
                println!("  Actual tokens ({}): ", token_count);
                for (i, token) in state.tokens.iter().enumerate() {
                    if i >= token_count {
                        break;
                    }
                    // Display the actual value being compared, not the C-compatible formatted version
                    // For tokens at index i, we need to show what would actually be compared
                    if i < expected_lines.len() {
                        let expected_line = expected_lines[i];
                        let parts: Vec<&str> = expected_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let expected_value = parts[1..].join(" ");
                            let actual_value = format_token_for_c_compatibility(token);
                            println!("    {} {} (comparing with: {})", token.token_type.to_char(), actual_value, expected_value);
                        } else {
                            println!("    {} {}", token.token_type.to_char(), format_token_for_c_compatibility(token));
                        }
                    } else {
                        println!("    {} {}", token.token_type.to_char(), format_token_for_c_compatibility(token));
                    }
                }
                println!();
            }
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    if failed > 0 {
        panic!("{} folding tests failed", failed);
    }
}

fn parse_test_file(content: &str) -> Option<(String, String, String)> {
    let lines: Vec<&str> = content.lines().collect();
    
    let mut test_name = None;
    let mut input = None;
    let mut expected = Vec::new();
    
    let mut section = "";
    
    for line in lines {
        let line = line.trim();
        if line == "--TEST--" {
            section = "test";
            continue;
        } else if line == "--INPUT--" {
            section = "input";
            continue;
        } else if line == "--EXPECTED--" {
            section = "expected";
            continue;
        } else if line.is_empty() {
            continue;
        }
        
        match section {
            "test" => {
                if test_name.is_none() {
                    test_name = Some(line.to_string());
                }
                // Ignore any additional lines in test section (they are comments)
            }
            "input" => {
                if input.is_none() {
                    input = Some(line.to_string());
                }
                // Only take the first non-empty line as input
            }
            "expected" => {
                expected.push(line.to_string());
            }
            _ => {}
        }
    }
    
    if let (Some(name), Some(inp), _) = (test_name, input, &expected) {
        Some((name, inp, expected.join("\n")))
    } else {
        None
    }
}

fn run_folding_test(input: &str, expected: &str) -> bool {
    let mut state = SqliState::new(input.as_bytes(), SqliFlags::FLAG_NONE);
    let token_count = state.fold_tokens();
    
    let expected_lines: Vec<&str> = expected.lines().collect();
    
    
    if token_count != expected_lines.len() {
        return false;
    }
    
    for (i, expected_line) in expected_lines.iter().enumerate() {
        if i >= state.tokens.len() {
            return false;
        }
        
        let token = &state.tokens[i];
        let parts: Vec<&str> = expected_line.split_whitespace().collect();
        
        if parts.len() < 2 {
            continue;
        }
        
        let expected_type_char = parts[0].chars().next().unwrap();
        let expected_value = parts[1..].join(" ");
        
        // Don't strip quotes from expected value for string tokens
        // The format_token_for_c_compatibility function reconstructs the quotes
        // so we need to compare with quotes included
        
        let actual_type_char = token.token_type.to_char();
        let actual_value = format_token_for_c_compatibility(token);
        
        if actual_type_char != expected_type_char || actual_value != expected_value {
            return false;
        }
    }
    
    true
}