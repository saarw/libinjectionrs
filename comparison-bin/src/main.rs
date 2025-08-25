use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libinjectionrs::{detect_sqli as rust_detect_sqli, detect_xss as rust_detect_xss};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Parser)]
#[command(name = "libinjection-compare")]
#[command(about = "Compare Rust and C implementations of libinjection")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare SQL injection detection
    Sqli {
        /// Input string to test
        #[arg(short, long)]
        input: Option<String>,
        
        /// File containing inputs (one per line)
        #[arg(short, long)]
        file: Option<PathBuf>,
        
        /// Output results in JSON format
        #[arg(long)]
        json: bool,
        
        /// Detection flags
        #[arg(long, default_value = "0")]
        flags: i32,
    },
    
    /// Compare XSS detection  
    Xss {
        /// Input string to test
        #[arg(short, long)]
        input: Option<String>,
        
        /// File containing inputs (one per line)
        #[arg(short, long)]
        file: Option<PathBuf>,
        
        /// Output results in JSON format
        #[arg(long)]
        json: bool,
        
        /// Detection flags
        #[arg(long, default_value = "0")]
        flags: i32,
    },
    
    /// Run differential testing on test corpus
    Test {
        /// Directory containing test files
        #[arg(short, long)]
        directory: PathBuf,
        
        /// Output detailed comparison report
        #[arg(long)]
        detailed: bool,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct SqliComparison {
    input: String,
    rust_result: RustSqliResult,
    c_result: CSqliResult,
    match_result: bool,
    match_fingerprint: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct RustSqliResult {
    is_injection: bool,
    fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CSqliResult {
    is_injection: bool,
    fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct XssComparison {
    input: String,
    rust_result: bool,
    c_result: bool,
    matches: bool,
}

fn call_c_sqli(input: &str, flags: i32) -> Result<CSqliResult> {
    let c_input = CString::new(input).context("Failed to create C string")?;
    
    unsafe {
        let result = harness_detect_sqli(
            c_input.as_ptr(),
            input.len(),
            flags,
        );
        
        let fingerprint = if result.is_sqli != 0 {
            let fp_cstr = std::ffi::CStr::from_ptr(result.fingerprint.as_ptr());
            fp_cstr.to_string_lossy().into_owned()
        } else {
            String::new()
        };
        
        Ok(CSqliResult {
            is_injection: result.is_sqli != 0,
            fingerprint,
        })
    }
}

fn call_c_xss(input: &str, flags: i32) -> Result<bool> {
    let c_input = CString::new(input).context("Failed to create C string")?;
    
    unsafe {
        let result = harness_detect_xss(
            c_input.as_ptr(),
            input.len(),
            flags,
        );
        
        Ok(result.is_xss != 0)
    }
}

fn compare_sqli_single(input: &str, flags: i32) -> Result<SqliComparison> {
    // Call Rust implementation
    let rust_result = rust_detect_sqli(input.as_bytes());
    
    // Call C implementation
    let c_result = call_c_sqli(input, flags)?;
    
    let rust_sqli_result = RustSqliResult {
        is_injection: rust_result.is_injection,
        fingerprint: rust_result.fingerprint.map(|f| f.to_string()),
    };
    
    let match_result = rust_sqli_result.is_injection == c_result.is_injection;
    let match_fingerprint = if rust_sqli_result.is_injection && c_result.is_injection {
        rust_sqli_result.fingerprint.as_ref().map_or(false, |fp| fp == &c_result.fingerprint)
    } else {
        true // Both safe, fingerprint doesn't matter
    };
    
    Ok(SqliComparison {
        input: input.to_string(),
        rust_result: rust_sqli_result,
        c_result,
        match_result,
        match_fingerprint,
    })
}

fn compare_xss_single(input: &str, flags: i32) -> Result<XssComparison> {
    // Call Rust implementation
    let rust_result = rust_detect_xss(input.as_bytes()).is_injection();
    
    // Call C implementation
    let c_result = call_c_xss(input, flags)?;
    
    Ok(XssComparison {
        input: input.to_string(),
        rust_result,
        c_result,
        matches: rust_result == c_result,
    })
}

fn read_inputs_from_file(file_path: &PathBuf) -> Result<Vec<String>> {
    let file = fs::File::open(file_path)
        .with_context(|| format!("Failed to open file: {:?}", file_path))?;
    let reader = BufReader::new(file);
    
    let mut inputs = Vec::new();
    for line in reader.lines() {
        let line = line.context("Failed to read line")?;
        if !line.trim().is_empty() {
            inputs.push(line.trim().to_string());
        }
    }
    
    Ok(inputs)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Sqli { input, file, json, flags } => {
            let inputs = if let Some(input) = input {
                vec![input]
            } else if let Some(file) = file {
                read_inputs_from_file(&file)?
            } else {
                anyhow::bail!("Either --input or --file must be specified");
            };
            
            let mut results = Vec::new();
            for input in inputs {
                let comparison = compare_sqli_single(&input, flags)?;
                results.push(comparison);
            }
            
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                for result in results {
                    println!("Input: {}", result.input);
                    println!("  Rust:  {:?} (fingerprint: {:?})", 
                             result.rust_result.is_injection, 
                             result.rust_result.fingerprint);
                    println!("  C:     {} (fingerprint: {})", 
                             result.c_result.is_injection, 
                             result.c_result.fingerprint);
                    println!("  Match: result={}, fingerprint={}", 
                             result.match_result, 
                             result.match_fingerprint);
                    println!();
                }
            }
        }
        
        Commands::Xss { input, file, json, flags } => {
            let inputs = if let Some(input) = input {
                vec![input]
            } else if let Some(file) = file {
                read_inputs_from_file(&file)?
            } else {
                anyhow::bail!("Either --input or --file must be specified");
            };
            
            let mut results = Vec::new();
            for input in inputs {
                let comparison = compare_xss_single(&input, flags)?;
                results.push(comparison);
            }
            
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                for result in results {
                    println!("Input: {}", result.input);
                    println!("  Rust: {}", result.rust_result);
                    println!("  C:    {}", result.c_result);
                    println!("  Match: {}", result.matches);
                    println!();
                }
            }
        }
        
        Commands::Test { directory, detailed } => {
            println!("Running differential tests from directory: {:?}", directory);
            println!("Detailed mode: {}", detailed);
            
            // TODO: Implement test corpus processing
            anyhow::bail!("Test command not yet implemented");
        }
    }
    
    Ok(())
}