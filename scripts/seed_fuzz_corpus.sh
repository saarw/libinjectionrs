#!/bin/bash

# Script to seed Rust fuzz corpus with test cases from libinjection-c
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
C_TESTS_DIR="$PROJECT_ROOT/libinjection-c/tests"
FUZZ_CORPUS_DIR="$PROJECT_ROOT/fuzz/corpus"

usage() {
    echo "Usage: $0 [sqli|xss|all]"
    echo "  sqli - seed SQL injection corpus"
    echo "  xss  - seed XSS corpus" 
    echo "  all  - seed both corpora"
    exit 1
}

seed_sqli_corpus() {
    echo "Seeding SQL injection corpus..."
    
    local corpus_dir="$FUZZ_CORPUS_DIR/fuzz_sqli"
    mkdir -p "$corpus_dir"
    
    local count=0
    for test_file in "$C_TESTS_DIR"/test-sqli-*.txt; do
        [ -e "$test_file" ] || continue
        
        # Extract the INPUT line (line 4)
        local input_line=$(sed -n '4p' < "$test_file")
        
        if [ -n "$input_line" ]; then
            # Create filename based on hash of content to avoid duplicates
            local hash=$(echo -n "$input_line" | shasum -a 1 | cut -d' ' -f1)
            local output_file="$corpus_dir/seed_sqli_${hash}"
            
            echo -n "$input_line" > "$output_file"
            count=$((count + 1))
        fi
    done
    
    echo "Added $count SQL injection test cases to corpus"
}

seed_xss_corpus() {
    echo "Seeding XSS corpus..."
    
    local corpus_dir="$FUZZ_CORPUS_DIR/fuzz_xss"
    mkdir -p "$corpus_dir"
    
    local count=0
    for test_file in "$C_TESTS_DIR"/test-html5-*.txt; do
        [ -e "$test_file" ] || continue
        
        # Extract the INPUT line (line 4)
        local input_line=$(sed -n '4p' < "$test_file")
        
        if [ -n "$input_line" ]; then
            # Create filename based on hash of content to avoid duplicates
            local hash=$(echo -n "$input_line" | shasum -a 1 | cut -d' ' -f1)
            local output_file="$corpus_dir/seed_xss_${hash}"
            
            echo -n "$input_line" > "$output_file"
            count=$((count + 1))
        fi
    done
    
    echo "Added $count XSS test cases to corpus"
}

# Check if libinjection-c tests directory exists
if [ ! -d "$C_TESTS_DIR" ]; then
    echo "Error: libinjection-c tests directory not found at $C_TESTS_DIR"
    echo "Make sure the libinjection-c submodule is initialized"
    exit 1
fi

# Parse command line argument
case "${1:-}" in
    sqli)
        seed_sqli_corpus
        ;;
    xss)
        seed_xss_corpus
        ;;
    all)
        seed_sqli_corpus
        seed_xss_corpus
        ;;
    *)
        usage
        ;;
esac

echo "Corpus seeding complete!"
echo ""
echo "You can now run fuzzing with:"
echo "  cargo fuzz run fuzz_sqli"
echo "  cargo fuzz run fuzz_xss"