#!/usr/bin/env python3

import subprocess
import time
import os

def run_benchmark_test():
    """Run performance comparison with optimized builds."""
    
    print("🚀 Performance Comparison: Rust vs Optimized C (-O3 -fno-omit-frame-pointer -g)")
    print("=" * 80)
    
    # Make sure we're in the right directory
    os.chdir("/Users/william/projects/libinjectionrs")
    
    print("\n📊 Running SQL injection benchmarks...")
    try:
        result = subprocess.run([
            "cargo", "bench", "--bench", "sqli_bench", "--", "--test"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ SQL injection benchmarks completed")
            print(f"Sample output: {result.stdout[:200]}...")
        else:
            print(f"❌ SQL benchmarks failed: {result.stderr[:200]}...")
    except subprocess.TimeoutExpired:
        print("⏰ SQL benchmarks timed out")
    except Exception as e:
        print(f"❌ Error running SQL benchmarks: {e}")
    
    print("\n📊 Running XSS detection benchmarks...")
    try:
        result = subprocess.run([
            "cargo", "bench", "--bench", "xss_bench", "--", "--test"  
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ XSS benchmarks completed")
            print(f"Sample output: {result.stdout[:200]}...")
        else:
            print(f"❌ XSS benchmarks failed: {result.stderr[:200]}...")
    except subprocess.TimeoutExpired:
        print("⏰ XSS benchmarks timed out")
    except Exception as e:
        print(f"❌ Error running XSS benchmarks: {e}")
    
    print("\n📊 Running differential benchmarks (Rust vs C)...")
    try:
        result = subprocess.run([
            "cargo", "bench", "--bench", "differential_bench", "--", "--test"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✅ Differential benchmarks completed")
            print(f"Sample output: {result.stdout[:300]}...")
        else:
            print(f"❌ Differential benchmarks failed: {result.stderr[:300]}...")
    except subprocess.TimeoutExpired:
        print("⏰ Differential benchmarks timed out")
    except Exception as e:
        print(f"❌ Error running differential benchmarks: {e}")
    
    print("\n💡 For detailed benchmark reports, check target/criterion/ directory")
    print("💡 Use 'cargo bench' without --test flag for full benchmark runs")
    
    # Test basic functionality
    print("\n🔧 Testing basic functionality...")
    try:
        result = subprocess.run([
            "cargo", "run", "-p", "libinjectionrs", "--example", "test_corpus"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            print(f"✅ Functionality test passed - {len(lines)} output lines")
            
            # Count detection results
            detected_lines = [line for line in lines if "🔴 DETECTED" in line]
            clean_lines = [line for line in lines if "🟢" in line]
            
            print(f"   - Detected threats: {len(detected_lines)}")
            print(f"   - Clean content: {len(clean_lines)}")
        else:
            print(f"❌ Functionality test failed: {result.stderr[:200]}...")
    except Exception as e:
        print(f"❌ Error in functionality test: {e}")
    
    print(f"\n📈 Optimization flags used for C library:")
    print("   -O3 -fno-omit-frame-pointer -g")
    print("   This ensures fair performance comparison with Rust --release builds")

if __name__ == "__main__":
    run_benchmark_test()