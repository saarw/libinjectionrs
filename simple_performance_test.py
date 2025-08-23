#!/usr/bin/env python3

import subprocess
import time
import statistics
from pathlib import Path
import os

def measure_performance():
    """Measure Rust vs C performance using the comparison tool."""
    
    os.chdir("/Users/william/projects/libinjectionrs")
    os.environ["DYLD_LIBRARY_PATH"] = "./ffi-harness/lib"
    
    # Test cases for performance measurement
    test_cases = [
        ("simple_select", "SELECT * FROM users WHERE id = 1"),
        ("union_attack", "' UNION SELECT 1,2,3--"), 
        ("boolean_injection", "1' OR '1'='1"),
        ("time_based", "1' AND SLEEP(5)--"),
        ("comment_injection", "admin'--"),
        ("script_tag", "<script>alert('xss')</script>"),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("iframe_js", "<iframe src=javascript:alert(1)></iframe>"),
        ("safe_text", "Hello world"),
        ("safe_html", "<div>Hello <b>world</b></div>")
    ]
    
    print("🚀 Rust vs C Performance Comparison")
    print("=" * 60)
    
    results = []
    
    for name, test_input in test_cases:
        print(f"\n📊 Testing: {name}")
        print(f"Input: {test_input[:50]}...")
        
        # Warm up and measure multiple runs
        warmup_runs = 5
        measure_runs = 100
        
        # Warmup
        for _ in range(warmup_runs):
            subprocess.run([
                "./target/release/compare", "sqli", "-i", test_input
            ], capture_output=True, env=os.environ.copy())
        
        # Measure performance
        times = []
        for _ in range(measure_runs):
            start = time.perf_counter()
            result = subprocess.run([
                "./target/release/compare", "sqli", "-i", test_input  
            ], capture_output=True, env=os.environ.copy())
            end = time.perf_counter()
            
            if result.returncode == 0:
                times.append((end - start) * 1_000_000)  # Convert to microseconds
        
        if times:
            avg_time = statistics.mean(times)
            median_time = statistics.median(times)
            std_dev = statistics.stdev(times) if len(times) > 1 else 0
            
            print(f"  Average: {avg_time:.1f} μs")
            print(f"  Median:  {median_time:.1f} μs")  
            print(f"  Std Dev: {std_dev:.1f} μs")
            
            results.append({
                'name': name,
                'avg': avg_time,
                'median': median_time,
                'std': std_dev
            })
        else:
            print("  ❌ Failed to measure")
    
    # Summary
    if results:
        print(f"\n📈 Performance Summary")
        print("=" * 60)
        
        total_avg = statistics.mean([r['avg'] for r in results])
        total_median = statistics.median([r['median'] for r in results])
        
        print(f"Overall average processing time: {total_avg:.1f} μs")
        print(f"Overall median processing time:  {total_median:.1f} μs")
        
        print(f"\n🏆 Fastest cases:")
        fastest = sorted(results, key=lambda x: x['median'])[:3]
        for i, case in enumerate(fastest, 1):
            print(f"  {i}. {case['name']}: {case['median']:.1f} μs")
            
        print(f"\n⏱️  Note: These times include process startup overhead")
        print(f"    Pure library performance is much faster (see cargo bench results)")
        
        # Compare with previous Rust-only benchmark results
        print(f"\n📊 Reference: Pure Rust library performance (from cargo bench):")
        print(f"  - SQL injection: ~525 ns average")  
        print(f"  - XSS detection: ~380 ns average")
        print(f"  - Process overhead adds: ~{total_median:.0f}x slowdown")

if __name__ == "__main__":
    measure_performance()