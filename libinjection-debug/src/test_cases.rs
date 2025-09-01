use crate::tokenizer_debug::{DebugConfig, TokenizerDebugger};
use colored::*;

pub fn run_all_tests(specific_case: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = get_builtin_test_cases();
    
    let cases_to_run: Vec<_> = if let Some(case_name) = specific_case {
        test_cases.into_iter()
            .filter(|(name, _)| name.contains(case_name))
            .collect()
    } else {
        test_cases
    };
    
    if cases_to_run.is_empty() {
        println!("{}", "No matching test cases found".bright_yellow());
        return Ok(());
    }
    
    println!("Running {} test case(s):", cases_to_run.len());
    println!();
    
    let mut passed = 0;
    let mut failed = 0;
    
    for (name, test_case) in cases_to_run {
        println!("{}: {}", "Test".bright_blue().bold(), name.bright_white());
        println!("Input: {}", test_case.input_desc.bright_cyan());
        
        let input_bytes = parse_test_input(&test_case.input);
        let mut config = DebugConfig::default();
        config.compare_c_rust = true;
        
        let debugger = TokenizerDebugger::new(config);
        match debugger.analyze(&input_bytes) {
            Ok(results) => {
                println!("Rust result: {} (fingerprint: '{}')", 
                        if results.is_sqli { "SQLi".bright_red() } else { "Clean".bright_green() },
                        results.fingerprint.bright_cyan());
                
                if let Some(expected) = &test_case.expected {
                    let matches_expected = results.fingerprint == expected.fingerprint && 
                                         results.is_sqli == expected.is_sqli;
                    
                    if matches_expected {
                        println!("{}", "✅ PASS".bright_green().bold());
                        passed += 1;
                    } else {
                        println!("{}", "❌ FAIL".bright_red().bold());
                        println!("Expected: {} (fingerprint: '{}')",
                                if expected.is_sqli { "SQLi".bright_red() } else { "Clean".bright_green() },
                                expected.fingerprint.bright_cyan());
                        failed += 1;
                    }
                } else {
                    println!("{}", "ℹ️  No expected result (exploratory test)".bright_yellow());
                }
                
                if results.differential_detected {
                    println!("{}", "⚠️  C/Rust differential detected".bright_yellow().bold());
                }
            }
            Err(e) => {
                println!("{}: {}", "Error".bright_red().bold(), e);
                failed += 1;
            }
        }
        
        println!();
    }
    
    // Summary
    println!("{}", "=== Test Summary ===".bright_blue().bold());
    println!("Passed: {}", passed.to_string().bright_green());
    println!("Failed: {}", failed.to_string().bright_red());
    println!("Total:  {}", (passed + failed).to_string().bright_white());
    
    if failed > 0 {
        std::process::exit(1);
    }
    
    Ok(())
}

struct TestCase {
    input: String,
    input_desc: String,
    expected: Option<ExpectedResult>,
    description: String,
}

struct ExpectedResult {
    fingerprint: String,
    is_sqli: bool,
}

fn get_builtin_test_cases() -> Vec<(String, TestCase)> {
    vec![
        ("basic_select".to_string(), TestCase {
            input: "SELECT * FROM users".to_string(),
            input_desc: "Basic SELECT query".to_string(),
            expected: Some(ExpectedResult {
                fingerprint: "UEok".to_string(),
                is_sqli: false,
            }),
            description: "Simple legitimate SQL query".to_string(),
        }),
        
        ("classic_injection".to_string(), TestCase {
            input: "' OR '1'='1".to_string(),
            input_desc: "Classic SQL injection".to_string(),
            expected: Some(ExpectedResult {
                fingerprint: "s&s".to_string(),
                is_sqli: true,
            }),
            description: "Basic OR-based SQL injection".to_string(),
        }),
        
        ("backtick_hash_case".to_string(), TestCase {
            input: "`n'#'".to_string(),
            input_desc: "Backtick with hash character (differential bug)".to_string(),
            expected: None, // This is what we're investigating
            description: "The failing case from fuzzing - C returns 'sos'/true, Rust returns 'n'/false".to_string(),
        }),
        
        ("hash_in_quotes".to_string(), TestCase {
            input: "'#'".to_string(),
            input_desc: "Hash character in single quotes".to_string(),
            expected: None,
            description: "Isolate the hash-in-quotes behavior".to_string(),
        }),
        
        ("simple_backtick".to_string(), TestCase {
            input: "`test`".to_string(),
            input_desc: "Simple backtick identifier".to_string(),
            expected: Some(ExpectedResult {
                fingerprint: "n".to_string(),
                is_sqli: false,
            }),
            description: "Basic MySQL backtick identifier".to_string(),
        }),
        
        ("unclosed_backtick".to_string(), TestCase {
            input: "`test".to_string(),
            input_desc: "Unclosed backtick".to_string(),
            expected: None,
            description: "Test behavior when backtick is not closed".to_string(),
        }),
        
        ("original_fuzzing_case".to_string(), TestCase {
            input: hex_to_string("01ffffff20606e2723"),
            input_desc: "Original fuzzing input (hex: 01ffffff20606e2723)".to_string(),
            expected: None,
            description: "The complete original failing input from fuzzing".to_string(),
        }),
        
        ("minimal_differential".to_string(), TestCase {
            input: "n'#'".to_string(),
            input_desc: "Minimal case without backtick".to_string(),
            expected: None,
            description: "Test if the issue occurs without the backtick".to_string(),
        }),
    ]
}

fn parse_test_input(input: &str) -> Vec<u8> {
    if input.starts_with("hex:") {
        hex::decode(&input[4..]).unwrap_or_else(|_| input.as_bytes().to_vec())
    } else {
        input.as_bytes().to_vec()
    }
}

fn hex_to_string(hex: &str) -> String {
    format!("hex:{}", hex)
}