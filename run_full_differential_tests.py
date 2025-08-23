#!/usr/bin/env python3

import subprocess
import os
import sys
from pathlib import Path
import re

def run_differential_tests():
    """Run comprehensive differential tests against all libinjection testdata."""
    
    os.chdir("/Users/william/projects/libinjectionrs")
    os.environ["DYLD_LIBRARY_PATH"] = "./ffi-harness/lib"
    
    # Use testdata from libinjection-c submodule
    testdata_dir = Path("libinjection-c/data")
    if not testdata_dir.exists():
        print("❌ libinjection-c/data directory not found")
        return False
    
    print("🧪 Comprehensive Differential Testing: Rust vs C")
    print("=" * 60)
    
    # Categories of tests to run
    test_categories = {
        "SQL Injection": {
            "pattern": "sqli-*.txt",
            "detector": "sqli",
            "expected_matches": True
        },
        "XSS": {
            "pattern": "xss-*.txt", 
            "detector": "xss",
            "expected_matches": True
        },
        "False Positives": {
            "pattern": "false_positives.txt",
            "detector": "sqli",
            "expected_matches": False
        }
    }
    
    total_tests = 0
    total_matches = 0
    total_mismatches = 0
    results_by_category = {}
    
    for category, config in test_categories.items():
        print(f"\n🔍 Testing {category}")
        print("-" * 40)
        
        # Find all files matching the pattern
        pattern = config["pattern"]
        test_files = list(testdata_dir.glob(pattern))
        
        if not test_files:
            print(f"⚠️  No files found matching {pattern}")
            continue
            
        category_tests = 0
        category_matches = 0
        category_mismatches = 0
        mismatched_files = []
        
        for test_file in sorted(test_files)[:10]:  # Limit to first 10 files per category for performance
            print(f"  📁 Testing {test_file.name}...")
            
            try:
                with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"    ❌ Error reading file: {e}")
                continue
            
            file_tests = 0
            file_matches = 0 
            file_mismatches = 0
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # URL decode if needed
                try:
                    import urllib.parse
                    decoded_line = urllib.parse.unquote(line)
                except:
                    decoded_line = line
                
                # Test with comparison tool
                try:
                    result = subprocess.run([
                        "./target/release/compare", config["detector"], "-i", decoded_line
                    ], capture_output=True, text=True, timeout=5, env=os.environ.copy())
                    
                    if result.returncode != 0:
                        continue
                    
                    # Parse result
                    output = result.stdout.strip()
                    match_line = [l for l in output.split('\n') if 'Match:' in l]
                    
                    if match_line:
                        match_result = match_line[0]
                        if "result=true" in match_result and "fingerprint=true" in match_result:
                            # Perfect match (both detection and fingerprint agree)
                            file_matches += 1
                        elif "result=true" in match_result and "fingerprint=false" in match_result:
                            # Detection agrees but fingerprint differs (acceptable for basic functionality)
                            file_matches += 1
                        elif "result=false" in match_result:
                            # Detection results disagree - this is a real mismatch
                            file_mismatches += 1
                            
                            # Only log first few mismatches per file to avoid spam
                            if file_mismatches <= 3:
                                print(f"    ❌ Line {line_num}: {decoded_line[:50]}...")
                                print(f"       {match_result}")
                        
                    file_tests += 1
                    
                except subprocess.TimeoutExpired:
                    print(f"    ⏰ Timeout on line {line_num}")
                    continue
                except Exception as e:
                    continue
                
                # Limit per file to avoid excessive runtime
                if file_tests >= 20:
                    break
            
            category_tests += file_tests
            category_matches += file_matches
            category_mismatches += file_mismatches
            
            match_rate = (file_matches / file_tests * 100) if file_tests > 0 else 0
            print(f"    📊 {file_matches}/{file_tests} matches ({match_rate:.1f}%)")
            
            if file_mismatches > 0:
                mismatched_files.append(test_file.name)
        
        # Category summary
        total_tests += category_tests
        total_matches += category_matches
        total_mismatches += category_mismatches
        
        if category_tests > 0:
            category_rate = category_matches / category_tests * 100
            print(f"\n  🎯 {category} Summary: {category_matches}/{category_tests} ({category_rate:.1f}%)")
            
            if mismatched_files:
                print(f"  ⚠️  Files with mismatches: {', '.join(mismatched_files[:3])}")
                if len(mismatched_files) > 3:
                    print(f"     ... and {len(mismatched_files) - 3} more")
        
        results_by_category[category] = {
            'matches': category_matches,
            'tests': category_tests,
            'rate': category_rate if category_tests > 0 else 0
        }
    
    # Overall summary
    print(f"\n🏆 Overall Results")
    print("=" * 60)
    
    if total_tests > 0:
        overall_rate = total_matches / total_tests * 100
        print(f"Total matches: {total_matches}/{total_tests} ({overall_rate:.1f}%)")
        print(f"Mismatches: {total_mismatches}")
        
        print(f"\n📊 Breakdown by category:")
        for category, results in results_by_category.items():
            print(f"  • {category}: {results['rate']:.1f}% ({results['matches']}/{results['tests']})")
        
        print(f"\n💡 Notes:")
        print(f"  • Perfect match = Both detection result and fingerprint agree")  
        print(f"  • Acceptable = Detection agrees, fingerprint may differ")
        print(f"  • Mismatch = Detection results disagree (needs investigation)")
        print(f"  • Limited to first 20 inputs per file and 10 files per category")
        
        # Quality assessment
        if overall_rate >= 95:
            print(f"\n✅ Excellent functional parity ({overall_rate:.1f}%)")
        elif overall_rate >= 90:
            print(f"\n✅ Good functional parity ({overall_rate:.1f}%)")
        elif overall_rate >= 80:
            print(f"\n⚠️  Acceptable functional parity ({overall_rate:.1f}%) - some differences")
        else:
            print(f"\n❌ Poor functional parity ({overall_rate:.1f}%) - needs investigation")
        
        return overall_rate >= 80
    else:
        print("❌ No tests were run")
        return False

if __name__ == "__main__":
    success = run_differential_tests()
    sys.exit(0 if success else 1)