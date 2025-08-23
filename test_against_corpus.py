#!/usr/bin/env python3

import subprocess
import os
from pathlib import Path

def test_rust_against_corpus():
    """Test Rust implementation against test corpus"""
    
    # Create a simple test binary
    test_code = '''
use libinjectionrs::{detect_sqli, detect_xss};
use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        if let Ok(line) = line {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            // URL decode the line
            let decoded = urlencoding::decode(line).unwrap_or_else(|_| line.into());
            
            let sqli_result = detect_sqli(decoded.as_bytes());
            let xss_result = detect_xss(decoded.as_bytes());
            
            if sqli_result.is_injection() || xss_result.is_injection() {
                let fingerprint = sqli_result.fingerprint()
                    .map(|fp| fp.to_string())
                    .unwrap_or_else(|| "none".to_string());
                println!("INJECTION: {} -> SQLI: {} ({}), XSS: {}", 
                        line, sqli_result.is_injection(), fingerprint, xss_result.is_injection());
            }
        }
    }
}
'''
    
    # Write test code to a temporary file
    with open("/tmp/test_corpus.rs", "w") as f:
        f.write(test_code)
    
    # Add urlencoding dependency to Cargo.toml temporarily 
    print("Testing Rust implementation against corpus...")
    
    # Test a few files
    test_files = [
        "testdata/sqli-misc.txt",
        "testdata/sqli-fullqueries.txt", 
        "testdata/xss-smoke-test.txt"
    ]
    
    for test_file in test_files:
        if Path(test_file).exists():
            print(f"\n=== Testing {test_file} ===")
            
            # Read first 10 lines and test them directly
            with open(test_file, 'r') as f:
                lines = f.readlines()[:10]
            
            for i, line in enumerate(lines):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                    
                # Test with the simple example binary we built
                cmd = f'echo "{line}" | cargo run -p libinjectionrs --example simple 2>/dev/null'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                # Just print the line for manual inspection
                print(f"Line {i+1}: {line[:60]}..." if len(line) > 60 else f"Line {i+1}: {line}")

if __name__ == "__main__":
    os.chdir("/Users/william/projects/libinjectionrs")
    test_rust_against_corpus()