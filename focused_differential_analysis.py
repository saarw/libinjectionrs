#!/usr/bin/env python3

import subprocess
import os

def analyze_specific_cases():
    """Analyze specific cases to understand the differences."""
    
    os.chdir("/Users/william/projects/libinjectionrs")
    os.environ["DYLD_LIBRARY_PATH"] = "./ffi-harness/lib"
    
    print("🔍 Focused Differential Analysis")
    print("=" * 50)
    
    # Test cases that should match between implementations
    test_cases = [
        # Known SQL injections
        ("' UNION SELECT 1,2,3--", "UNION attack"),
        ("1' OR '1'='1", "Classic boolean injection"),
        ("admin'--", "Comment injection"), 
        ("' OR 1=1--", "Basic OR injection"),
        
        # Legitimate SQL (should both detect as injection in libinjection)
        ("SELECT * FROM users WHERE id = 1", "Normal SELECT"),
        ("select 1 from foo where", "Incomplete SELECT"),
        ("INSERT INTO table VALUES (1)", "Normal INSERT"),
        
        # XSS cases
        ("<script>alert(1)</script>", "Script tag"),
        ("<img src=x onerror=alert(1)>", "Event handler"),
        ("javascript:alert(1)", "JavaScript protocol"),
        ("<svg onload=alert(1)>", "SVG with onload"),
        
        # Safe content
        ("Hello world", "Plain text"),
        ("user@example.com", "Email address"),
        ("http://example.com", "URL"),
    ]
    
    sqli_matches = 0
    sqli_total = 0
    xss_matches = 0
    xss_total = 0
    
    print("\n📊 SQL Injection Test Cases:")
    print("-" * 30)
    
    for test_input, description in test_cases[:7]:  # First 7 are SQL cases
        try:
            result = subprocess.run([
                "./target/release/compare", "sqli", "-i", test_input
            ], capture_output=True, text=True, timeout=5, env=os.environ.copy())
            
            if result.returncode == 0:
                output = result.stdout.strip()
                lines = output.split('\n')
                
                rust_line = next((l for l in lines if 'Rust:' in l), '')
                c_line = next((l for l in lines if 'C:' in l), '')
                match_line = next((l for l in lines if 'Match:' in l), '')
                
                rust_result = 'true' in rust_line
                c_result = 'true' in c_line
                
                status = "✅" if rust_result == c_result else "❌"
                print(f"{status} {description:25} | Rust: {rust_result:5} | C: {c_result:5}")
                
                if rust_result == c_result:
                    sqli_matches += 1
                sqli_total += 1
            else:
                print(f"❌ {description:25} | Error running test")
                sqli_total += 1
                
        except Exception as e:
            print(f"❌ {description:25} | Exception: {str(e)[:30]}")
            sqli_total += 1
    
    print(f"\nSQL Injection Agreement: {sqli_matches}/{sqli_total} ({sqli_matches/sqli_total*100 if sqli_total > 0 else 0:.1f}%)")
    
    print("\n📊 XSS Test Cases:")
    print("-" * 30)
    
    for test_input, description in test_cases[7:11]:  # XSS cases
        try:
            result = subprocess.run([
                "./target/release/compare", "xss", "-i", test_input
            ], capture_output=True, text=True, timeout=5, env=os.environ.copy())
            
            if result.returncode == 0:
                output = result.stdout.strip()
                lines = output.split('\n')
                
                rust_line = next((l for l in lines if 'Rust:' in l), '')
                c_line = next((l for l in lines if 'C:' in l), '')
                
                rust_result = 'true' in rust_line
                c_result = 'true' in c_line
                
                status = "✅" if rust_result == c_result else "❌"
                print(f"{status} {description:25} | Rust: {rust_result:5} | C: {c_result:5}")
                
                if rust_result == c_result:
                    xss_matches += 1
                xss_total += 1
            else:
                print(f"❌ {description:25} | Error running test")
                xss_total += 1
                
        except Exception as e:
            print(f"❌ {description:25} | Exception: {str(e)[:30]}")
            xss_total += 1
    
    print(f"\nXSS Agreement: {xss_matches}/{xss_total} ({xss_matches/xss_total*100 if xss_total > 0 else 0:.1f}%)")
    
    print("\n📊 Safe Content Test Cases:")
    print("-" * 30)
    
    safe_matches = 0
    safe_total = 0
    
    for test_input, description in test_cases[11:]:  # Safe cases
        try:
            result = subprocess.run([
                "./target/release/compare", "sqli", "-i", test_input
            ], capture_output=True, text=True, timeout=5, env=os.environ.copy())
            
            if result.returncode == 0:
                output = result.stdout.strip()
                lines = output.split('\n')
                
                rust_line = next((l for l in lines if 'Rust:' in l), '')
                c_line = next((l for l in lines if 'C:' in l), '')
                
                rust_result = 'true' in rust_line
                c_result = 'true' in c_line
                
                status = "✅" if rust_result == c_result else "❌"
                print(f"{status} {description:25} | Rust: {rust_result:5} | C: {c_result:5}")
                
                if rust_result == c_result:
                    safe_matches += 1
                safe_total += 1
                
        except Exception as e:
            print(f"❌ {description:25} | Exception: {str(e)[:30]}")
            safe_total += 1
    
    print(f"\nSafe Content Agreement: {safe_matches}/{safe_total} ({safe_matches/safe_total*100 if safe_total > 0 else 0:.1f}%)")
    
    # Overall summary
    total_matches = sqli_matches + xss_matches + safe_matches
    total_tests = sqli_total + xss_total + safe_total
    overall_rate = total_matches / total_tests * 100 if total_tests > 0 else 0
    
    print(f"\n🎯 Overall Agreement: {total_matches}/{total_tests} ({overall_rate:.1f}%)")
    
    print(f"\n💭 Analysis:")
    if sqli_matches < sqli_total * 0.5:
        print("  • SQL injection detection has significant differences")
        print("  • Rust implementation may be more conservative")
        print("  • Need to review tokenizer and fingerprinting logic")
    
    if xss_matches == xss_total and xss_total > 0:
        print("  • XSS detection appears to work correctly")
    elif xss_matches < xss_total * 0.8:
        print("  • XSS detection has some differences")
    
    if safe_matches == safe_total and safe_total > 0:
        print("  • Safe content handling is consistent")

if __name__ == "__main__":
    analyze_specific_cases()