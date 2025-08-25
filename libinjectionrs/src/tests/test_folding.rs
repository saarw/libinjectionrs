use crate::sqli::*;
use std::fs;
use std::path::Path;

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
                    println!("    {} {}", token.token_type.to_char(), token.value_as_str());
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
    let mut in_expected = false;
    
    for line in lines {
        let line = line.trim();
        if line == "--TEST--" {
            continue;
        } else if line == "--INPUT--" {
            in_expected = false;
            continue;
        } else if line == "--EXPECTED--" {
            in_expected = true;
            continue;
        } else if line.is_empty() {
            continue;
        }
        
        if test_name.is_none() && !in_expected {
            test_name = Some(line.to_string());
        } else if input.is_none() && !in_expected {
            input = Some(line.to_string());
        } else if in_expected {
            expected.push(line.to_string());
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
        
        let actual_type_char = token.token_type.to_char();
        let actual_value = token.value_as_str();
        
        if actual_type_char != expected_type_char || actual_value != expected_value {
            return false;
        }
    }
    
    true
}