use crate::tokenizer_debug::AnalysisResults;
use crate::Cli;
use colored::*;
use std::io::{self, Write};

pub fn output_text(results: &AnalysisResults, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Input Information
    println!("{}", "=== Input Analysis ===".bright_blue().bold());
    println!("Original: {}", results.input_info.original_string.bright_white());
    println!("Bytes: {:?}", results.input_info.byte_array);
    println!("Hex: {}", results.input_info.hex_representation.bright_cyan());
    println!("Length: {} bytes", results.input_info.length);
    println!("Flags: {}", results.input_info.flags.bright_yellow());
    println!();
    
    // Character-by-character analysis
    if !results.character_analysis.is_empty() {
        println!("{}", "=== Character Analysis ===".bright_blue().bold());
        for char_info in &results.character_analysis {
            println!("Pos {}: {} ({}) -> {} -> {}", 
                    char_info.position.to_string().bright_green(),
                    char_info.byte_value.to_string().bright_white(),
                    char_info.char_repr.bright_cyan(),
                    char_info.char_type.bright_yellow(),
                    char_info.parser_function.bright_magenta());
        }
        println!();
    }
    
    // Raw tokenization (if available)
    if !results.raw_tokens.is_empty() && !cli.raw_tokens_only {
        println!("{}", "=== Raw Tokenization ===".bright_blue().bold());
        for token in &results.raw_tokens {
            println!("{}", token.to_string().bright_white());
        }
        println!();
    }
    
    // Folded tokens
    if !cli.raw_tokens_only {
        println!("{}", "=== Final Tokens ===".bright_blue().bold());
        for token in &results.folded_tokens {
            let mut token_str = token.to_string();
            if let (Some(open), Some(close)) = (token.str_open, token.str_close) {
                token_str = format!("{} [{}...{}]", token_str, open, close);
            }
            println!("{}", token_str.bright_white());
        }
        println!();
    }
    
    // Final Results
    println!("{}", "=== Analysis Results ===".bright_blue().bold());
    println!("Fingerprint: {}", results.fingerprint.bright_cyan().bold());
    
    let result_text = if results.is_sqli { "TRUE".bright_red().bold() } else { "FALSE".bright_green().bold() };
    println!("SQL Injection: {}", result_text);
    
    // C Comparison (if available)
    if let Some(ref c_results) = results.c_results {
        println!();
        println!("{}", "=== C Implementation Comparison ===".bright_blue().bold());
        println!("C Fingerprint: {}", c_results.fingerprint.bright_cyan().bold());
        
        let c_result_text = if c_results.is_sqli { "TRUE".bright_red().bold() } else { "FALSE".bright_green().bold() };
        println!("C SQL Injection: {}", c_result_text);
        
        // Show differential if detected
        if results.differential_detected {
            println!();
            println!("{}", "❌ DIFFERENTIAL DETECTED".bright_red().bold());
            
            if results.fingerprint != c_results.fingerprint {
                println!("  Fingerprint mismatch:");
                println!("    Rust: {}", results.fingerprint.bright_cyan());
                println!("    C:    {}", c_results.fingerprint.bright_cyan());
            }
            
            if results.is_sqli != c_results.is_sqli {
                println!("  Detection mismatch:");
                println!("    Rust: {}", if results.is_sqli { "TRUE".bright_red() } else { "FALSE".bright_green() });
                println!("    C:    {}", if c_results.is_sqli { "TRUE".bright_red() } else { "FALSE".bright_green() });
            }
        } else if cli.compare_c_rust {
            println!();
            println!("{}", "✅ C and Rust implementations match".bright_green().bold());
        }
    }
    
    Ok(())
}

pub fn output_json(results: &AnalysisResults) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(results)?);
    Ok(())
}

pub fn output_csv(results: &AnalysisResults) -> Result<(), Box<dyn std::error::Error>> {
    // CSV header
    println!("token_index,token_type,value,position,length,str_open,str_close");
    
    // Output tokens
    for token in &results.folded_tokens {
        let str_open = token.str_open.map(|c| c.to_string()).unwrap_or_default();
        let str_close = token.str_close.map(|c| c.to_string()).unwrap_or_default();
        
        println!("{},{},{},{},{},{},{}", 
                token.index,
                token.token_type,
                escape_csv(&token.value),
                token.position,
                token.length,
                str_open,
                str_close);
    }
    
    Ok(())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn output_diff(rust_results: &AnalysisResults, c_results: &crate::tokenizer_debug::CResults) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Differential Analysis ===".bright_blue().bold());
    
    // Compare fingerprints
    if rust_results.fingerprint != c_results.fingerprint {
        println!("{}", "Fingerprint Difference:".bright_yellow().bold());
        println!("  Rust: {}", rust_results.fingerprint.bright_cyan());
        println!("  C:    {}", c_results.fingerprint.bright_cyan());
        println!();
    }
    
    // Compare detection results
    if rust_results.is_sqli != c_results.is_sqli {
        println!("{}", "Detection Difference:".bright_yellow().bold());
        println!("  Rust: {}", if rust_results.is_sqli { "SQLi".bright_red() } else { "Clean".bright_green() });
        println!("  C:    {}", if c_results.is_sqli { "SQLi".bright_red() } else { "Clean".bright_green() });
        println!();
    }
    
    // Compare token counts
    if rust_results.folded_tokens.len() != c_results.tokens.len() {
        println!("{}", "Token Count Difference:".bright_yellow().bold());
        println!("  Rust: {} tokens", rust_results.folded_tokens.len());
        println!("  C:    {} tokens", c_results.tokens.len());
        println!();
    }
    
    // Side-by-side token comparison
    println!("{}", "Token Comparison:".bright_yellow().bold());
    let max_tokens = rust_results.folded_tokens.len().max(c_results.tokens.len());
    
    for i in 0..max_tokens {
        let rust_token = rust_results.folded_tokens.get(i);
        let c_token = c_results.tokens.get(i);
        
        match (rust_token, c_token) {
            (Some(r), Some(c)) => {
                if r.token_type != c.token_type || r.value != c.value {
                    println!("  {}: {} vs {}", 
                            i,
                            format!("{} '{}'", r.token_type, r.value).bright_cyan(),
                            format!("{} '{}'", c.token_type, c.value).bright_magenta());
                } else {
                    println!("  {}: {} (match)", i, format!("{} '{}'", r.token_type, r.value).bright_green());
                }
            }
            (Some(r), None) => {
                println!("  {}: {} vs {}", 
                        i,
                        format!("{} '{}'", r.token_type, r.value).bright_cyan(),
                        "MISSING".bright_red());
            }
            (None, Some(c)) => {
                println!("  {}: {} vs {}", 
                        i,
                        "MISSING".bright_red(),
                        format!("{} '{}'", c.token_type, c.value).bright_magenta());
            }
            (None, None) => break,
        }
    }
    
    Ok(())
}