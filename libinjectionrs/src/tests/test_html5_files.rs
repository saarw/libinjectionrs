use std::fs;
use std::path::Path;
use crate::xss::{Html5State, Html5Flags};

#[derive(Debug)]
struct TestCase {
    name: String,
    input: String,
    expected: String,
}

fn parse_test_file(content: &str) -> Option<TestCase> {
    let lines = content.lines();
    let mut state = 0; // 0=looking for --TEST--, 1=reading test name, 2=reading input, 3=reading expected
    let mut test_name = String::new();
    let mut input = String::new();
    let mut expected = String::new();

    for line in lines {
        match state {
            0 => {
                if line == "--TEST--" {
                    state = 1;
                }
            }
            1 => {
                if line == "--INPUT--" {
                    state = 2;
                } else if !line.is_empty() {
                    test_name.push_str(line);
                }
            }
            2 => {
                if line == "--EXPECTED--" {
                    state = 3;
                } else {
                    if !input.is_empty() {
                        input.push('\n');
                    }
                    input.push_str(line);
                }
            }
            3 => {
                if !line.is_empty() {
                    if !expected.is_empty() {
                        expected.push('\n');
                    }
                    expected.push_str(line);
                }
            }
            _ => {}
        }
    }

    if state == 3 {
        Some(TestCase {
            name: test_name,
            input,
            expected,
        })
    } else {
        None
    }
}

fn format_html5_token(state: &Html5State) -> String {
    let token_data = std::str::from_utf8(state.token_start).unwrap_or("<invalid utf8>");
    format!("{},{},{}", state.token_type, state.token_len, token_data)
}

fn run_html5_tokenization(input: &str) -> String {
    let input_bytes = input.as_bytes();
    let mut state = Html5State::new(input_bytes, Html5Flags::DataState);
    let mut result = Vec::new();

    while state.next() {
        result.push(format_html5_token(&state));
    }

    result.join("\n")
}

fn run_single_html5_test(file_path: &Path) -> Result<(), String> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read file {:?}: {}", file_path, e))?;

    let test_case = parse_test_file(&content)
        .ok_or_else(|| format!("Failed to parse test file {:?}", file_path))?;

    let actual = run_html5_tokenization(&test_case.input);

    if actual != test_case.expected {
        return Err(format!(
            "Test failed for {:?}\nTest: {}\nInput: {:?}\nExpected: {:?}\nActual: {:?}",
            file_path, test_case.name, test_case.input, test_case.expected, actual
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_all_html5_files() {
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
                if filename.starts_with("test-html5-") && filename.ends_with(".txt") {
                    test_files.push(path);
                }
            }
        }

        test_files.sort();
        
        println!("Found {} HTML5 test files", test_files.len());

        for test_file in &test_files {
            match run_single_html5_test(test_file) {
                Ok(()) => {
                    println!("✓ {:?}", test_file.file_name().unwrap());
                }
                Err(e) => {
                    println!("✗ {:?}", test_file.file_name().unwrap());
                    failures.push(format!("{}: {}", test_file.display(), e));
                }
            }
        }

        if !failures.is_empty() {
            println!("\n{} test(s) failed:", failures.len());
            for failure in &failures {
                println!("  {}", failure);
            }
            panic!("{} HTML5 test(s) failed", failures.len());
        }

        println!("All {} HTML5 tests passed!", test_files.len());
    }

    #[test]
    fn test_single_html5_example() {
        // Test a simple case first
        let input = "foo";
        let expected = "DATA_TEXT,3,foo";
        let actual = run_html5_tokenization(input);
        
        assert_eq!(actual, expected, "Simple HTML5 tokenization test failed");
    }
}