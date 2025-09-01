use crate::tokenizer_debug::{CResults, TokenInfo};
use std::process::{Command, Stdio};
use std::io::Write;

pub struct CTokenizerHarness {
    harness_path: String,
}

impl CTokenizerHarness {
    pub fn new() -> Self {
        Self {
            harness_path: "c_harness/debug_harness".to_string(),
        }
    }
    
    pub fn analyze(&self, input: &[u8]) -> Result<CResults, Box<dyn std::error::Error>> {
        // Check if C harness exists
        if !std::path::Path::new(&self.harness_path).exists() {
            return Err("C harness not built. Run 'make' in c_harness/ directory".into());
        }
        
        // Call C harness with input
        let mut cmd = Command::new(&self.harness_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // Send input to C harness
        if let Some(stdin) = cmd.stdin.as_mut() {
            stdin.write_all(input)?;
            stdin.flush()?;
        }
        
        // Get output
        let output = cmd.wait_with_output()?;
        
        if !output.status.success() {
            return Err(format!("C harness failed: {}", 
                              String::from_utf8_lossy(&output.stderr)).into());
        }
        
        // Parse C harness output
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_c_output(&stdout)
    }
    
    fn parse_c_output(&self, output: &str) -> Result<CResults, Box<dyn std::error::Error>> {
        // Expected C harness output format:
        // FINGERPRINT: sos
        // IS_SQLI: 1
        // TOKEN_COUNT: 3
        // TOKEN_0: STRING '' 0 1
        // TOKEN_1: OPERATOR '#' 1 1  
        // TOKEN_2: STRING '' 2 1
        
        let mut fingerprint = String::new();
        let mut is_sqli = false;
        let mut tokens = Vec::new();
        
        for line in output.lines() {
            let line = line.trim();
            
            if line.starts_with("FINGERPRINT: ") {
                fingerprint = line[13..].to_string();
            } else if line.starts_with("IS_SQLI: ") {
                is_sqli = &line[9..] == "1";
            } else if line.starts_with("TOKEN_") {
                if let Some(token) = self.parse_token_line(line)? {
                    tokens.push(token);
                }
            }
        }
        
        Ok(CResults {
            fingerprint,
            is_sqli,
            tokens,
        })
    }
    
    fn parse_token_line(&self, line: &str) -> Result<Option<TokenInfo>, Box<dyn std::error::Error>> {
        // Parse: TOKEN_0: STRING 'value' 0 1
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None);
        }
        
        // Extract token index from TOKEN_N:
        let index_part = parts[0].strip_suffix(':').unwrap_or(parts[0]);
        let index = index_part.strip_prefix("TOKEN_")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        
        let token_type = parts[1].to_string();
        let value = parts[2].trim_matches('\'').to_string();
        let position = parts[3].parse::<usize>().unwrap_or(0);
        let length = parts[4].parse::<usize>().unwrap_or(0);
        
        Ok(Some(TokenInfo {
            index,
            token_type,
            value,
            position,
            length,
            str_open: None, // TODO: Parse from C output if needed
            str_close: None,
        }))
    }
}

impl Default for CTokenizerHarness {
    fn default() -> Self {
        Self::new()
    }
}