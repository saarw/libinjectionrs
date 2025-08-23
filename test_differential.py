#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

def test_rust_only():
    """Test just the Rust implementation to validate basic functionality."""
    # Test a few basic cases
    test_cases = [
        "SELECT * FROM users WHERE id = 1",  # Normal SQL
        "1' OR '1'='1",                      # SQL injection
        "<script>alert('xss')</script>",     # XSS
        "Hello world"                        # Normal text
    ]
    
    print("Testing Rust-only implementation...")
    
    # Use the built binary directly without cargo run to avoid library issues
    binary_path = Path("target/debug/compare")
    if not binary_path.exists():
        print("Binary not found, building first...")
        result = subprocess.run(["cargo", "build", "-p", "libinjection-comparison"], 
                               capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Build failed: {result.stderr}")
            return
    
    for test_input in test_cases:
        print(f"\nTesting: {test_input}")
        
        # Test SQL injection detection
        result = subprocess.run(
            ["python3", "-c", f"""
import subprocess
import os
os.chdir('/Users/william/projects/libinjectionrs')
result = subprocess.run(['cargo', 'run', '-p', 'libinjectionrs', '--bin', 'detect_sqli'], 
                       input='{test_input}', text=True, capture_output=True)
print(f'Rust SQLI: {{result.stdout.strip()}}')
"""], capture_output=True, text=True)
        print(result.stdout.strip())

if __name__ == "__main__":
    test_rust_only()