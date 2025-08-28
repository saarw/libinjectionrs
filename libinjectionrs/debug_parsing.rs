use crate::sqli::*;
use std::fs;

pub fn debug_test_019() {
    let test_file = "../libinjection-c/tests/test-folding-019.txt";
    let content = fs::read_to_string(test_file).unwrap();
    
    println!("=== Raw file content ===");
    println!("{}", content);
    
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
                println!("Test section line: '{}'", line);
            }
            "input" => {
                if input.is_none() {
                    input = Some(line.to_string());
                }
                println!("Input section line: '{}'", line);
            }
            "expected" => {
                expected.push(line.to_string());
                println!("Expected section line: '{}'", line);
            }
            _ => {}
        }
    }
    
    println!("\nParsed results:");
    println!("Test name: {:?}", test_name);
    println!("Input: {:?}", input);
    println!("Expected: {:?}", expected);
    
    if let (Some(name), Some(inp), _) = (test_name, input, &expected) {
        println!("\n=== Running test ===");
        println!("Name: {}", name);
        println!("Input: {}", inp);
        
        let mut state = SqliState::new(inp.as_bytes(), SqliFlags::FLAG_NONE);
        let token_count = state.fold_tokens();
        
        println!("Actual output:");
        for token in &state.tokens[..token_count] {
            println!("{} {}", token.token_type.to_char(), token.value_as_str());
        }
    }
}