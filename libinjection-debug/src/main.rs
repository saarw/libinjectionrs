use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::PathBuf;

mod tokenizer_debug;
mod comparison;
mod formatters;
mod test_cases;

use tokenizer_debug::{DebugConfig, TokenizerDebugger};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "libinjection-debug")]
#[command(about = "Comprehensive debugging tool for libinjection tokenization")]
struct Cli {
    /// Input to analyze (string, hex, or file)
    input: Option<String>,
    
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Input is hexadecimal (e.g., "01ff20")
    #[arg(long)]
    hex: bool,
    
    /// Input is base64 encoded
    #[arg(long)]
    base64: bool,
    
    /// Read input from file
    #[arg(long)]
    file: Option<PathBuf>,
    
    /// SQL flags to use (default: FLAG_SQL_ANSI)
    #[arg(long, default_value = "FLAG_SQL_ANSI")]
    flags: String,
    
    /// Show step-by-step tokenization
    #[arg(long)]
    step_by_step: bool,
    
    /// Interactive mode (pause at each step)
    #[arg(long)]
    interactive: bool,
    
    /// Show only raw tokens (before folding)
    #[arg(long)]
    raw_tokens_only: bool,
    
    /// Compare C and Rust implementations
    #[arg(long)]
    compare_c_rust: bool,
    
    /// Show only differences between C and Rust
    #[arg(long)]
    diff_only: bool,
    
    /// Output format: text, json, csv
    #[arg(long, default_value = "text")]
    output: String,
    
    /// Export internal state information
    #[arg(long)]
    export_state: bool,
    
    /// Trace folding operations
    #[arg(long)]
    trace_folding: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run built-in test cases
    Test {
        /// Specific test case to run
        case: Option<String>,
    },
    /// Compare multiple inputs
    Batch {
        /// File containing inputs (one per line)
        inputs_file: PathBuf,
    },
    /// Interactive debugging session
    Interactive,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Test { case }) => {
            run_test_cases(case.as_deref())?;
        }
        Some(Commands::Batch { inputs_file }) => {
            run_batch_analysis(inputs_file)?;
        }
        Some(Commands::Interactive) => {
            run_interactive_mode()?;
        }
        None => {
            // Main analysis mode
            let input_bytes = get_input_bytes(&cli)?;
            let config = create_debug_config(&cli)?;
            
            let debugger = TokenizerDebugger::new(config);
            let results = debugger.analyze(&input_bytes)?;
            
            match cli.output.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&results)?),
                "csv" => formatters::output_csv(&results)?,
                _ => formatters::output_text(&results, &cli)?,
            }
        }
    }
    
    Ok(())
}

fn get_input_bytes(cli: &Cli) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(file_path) = &cli.file {
        return Ok(fs::read(file_path)?);
    }
    
    let input_str = cli.input.as_ref()
        .ok_or("Input required (use --help for options)")?;
    
    if cli.hex {
        Ok(hex::decode(input_str.replace(" ", "").replace("0x", ""))?)
    } else if cli.base64 {
        use base64::{Engine as _, engine::general_purpose};
        Ok(general_purpose::STANDARD.decode(input_str)?)
    } else {
        Ok(input_str.as_bytes().to_vec())
    }
}

fn create_debug_config(cli: &Cli) -> Result<DebugConfig, Box<dyn std::error::Error>> {
    Ok(DebugConfig {
        flags: cli.flags.clone(),
        step_by_step: cli.step_by_step,
        interactive: cli.interactive,
        raw_tokens_only: cli.raw_tokens_only,
        compare_c_rust: cli.compare_c_rust,
        diff_only: cli.diff_only,
        export_state: cli.export_state,
        trace_folding: cli.trace_folding,
        verbose: cli.verbose,
    })
}

fn run_test_cases(case: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Built-in Test Cases ===".bright_blue().bold());
    test_cases::run_all_tests(case)
}

fn run_batch_analysis(inputs_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Batch Analysis ===".bright_blue().bold());
    let contents = fs::read_to_string(inputs_file)?;
    
    for (line_num, line) in contents.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        
        println!("\n{} {}: {}", 
                "Input".bright_green(), 
                line_num + 1, 
                line.bright_white());
        
        let input_bytes = line.as_bytes().to_vec();
        let config = DebugConfig::default();
        let debugger = TokenizerDebugger::new(config);
        
        match debugger.analyze(&input_bytes) {
            Ok(results) => {
                formatters::output_text(&results, &Cli::parse_from(vec!["prog"]))?;
            }
            Err(e) => {
                println!("{}: {}", "Error".bright_red(), e);
            }
        }
    }
    
    Ok(())
}

fn run_interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Interactive Debugging Session ===".bright_blue().bold());
    println!("Enter 'help' for commands, 'quit' to exit");
    
    loop {
        print!("debug> ");
        use std::io::{self, Write};
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        match input {
            "quit" | "exit" => break,
            "help" => show_interactive_help(),
            "" => continue,
            _ => {
                let input_bytes = input.as_bytes().to_vec();
                let mut config = DebugConfig::default();
                config.interactive = true;
                config.step_by_step = true;
                
                let debugger = TokenizerDebugger::new(config);
                match debugger.analyze(&input_bytes) {
                    Ok(results) => {
                        formatters::output_text(&results, &Cli::parse_from(vec!["prog"]))?;
                    }
                    Err(e) => {
                        println!("{}: {}", "Error".bright_red(), e);
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn show_interactive_help() {
    println!("{}", "Available commands:".bright_yellow());
    println!("  help           - Show this help");
    println!("  quit/exit      - Exit interactive mode");
    println!("  <input>        - Analyze the input string");
    println!("  hex:01ff20     - Analyze hex input");
    println!("  base64:<data>  - Analyze base64 input");
}