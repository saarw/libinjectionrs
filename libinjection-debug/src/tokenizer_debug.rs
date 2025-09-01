use libinjectionrs::sqli::{SqliState, SqliFlags};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone)]
pub struct DebugConfig {
    pub flags: String,
    pub step_by_step: bool,
    pub interactive: bool,
    pub raw_tokens_only: bool,
    pub compare_c_rust: bool,
    pub diff_only: bool,
    pub export_state: bool,
    pub trace_folding: bool,
    pub verbose: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            flags: "FLAG_SQL_ANSI".to_string(),
            step_by_step: false,
            interactive: false,
            raw_tokens_only: false,
            compare_c_rust: false,
            diff_only: false,
            export_state: false,
            trace_folding: false,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub index: usize,
    pub token_type: String,
    pub value: String,
    pub position: usize,
    pub length: usize,
    pub str_open: Option<char>,
    pub str_close: Option<char>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterAnalysis {
    pub position: usize,
    pub byte_value: u8,
    pub char_repr: String,
    pub char_type: String,
    pub parser_function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub input_info: InputInfo,
    pub character_analysis: Vec<CharacterAnalysis>,
    pub raw_tokens: Vec<TokenInfo>,
    pub folded_tokens: Vec<TokenInfo>,
    pub fingerprint: String,
    pub is_sqli: bool,
    pub c_results: Option<CResults>,
    pub differential_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    pub original_string: String,
    pub byte_array: Vec<u8>,
    pub hex_representation: String,
    pub flags: String,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CResults {
    pub fingerprint: String,
    pub is_sqli: bool,
    pub tokens: Vec<TokenInfo>,
}

pub struct TokenizerDebugger {
    config: DebugConfig,
}

impl TokenizerDebugger {
    pub fn new(config: DebugConfig) -> Self {
        Self { config }
    }
    
    pub fn analyze(&self, input: &[u8]) -> Result<AnalysisResults, Box<dyn std::error::Error>> {
        let input_info = self.create_input_info(input);
        
        if self.config.verbose {
            println!("Analyzing input: {} bytes", input.len());
        }
        
        // Character-by-character analysis
        let character_analysis = if self.config.step_by_step {
            self.analyze_characters(input)?
        } else {
            Vec::new()
        };
        
        // Rust tokenization analysis
        let rust_results = self.analyze_rust_tokenization(input)?;
        
        // C tokenization analysis (if requested)
        let c_results = if self.config.compare_c_rust {
            Some(self.analyze_c_tokenization(input)?)
        } else {
            None
        };
        
        // Detect differentials
        let differential_detected = if let Some(ref c_res) = c_results {
            c_res.is_sqli != rust_results.is_sqli || c_res.fingerprint != rust_results.fingerprint
        } else {
            false
        };
        
        Ok(AnalysisResults {
            input_info,
            character_analysis,
            raw_tokens: rust_results.raw_tokens,
            folded_tokens: rust_results.folded_tokens,
            fingerprint: rust_results.fingerprint,
            is_sqli: rust_results.is_sqli,
            c_results,
            differential_detected,
        })
    }
    
    fn create_input_info(&self, input: &[u8]) -> InputInfo {
        let original_string = String::from_utf8_lossy(input).to_string();
        let hex_representation = hex::encode(input);
        
        InputInfo {
            original_string,
            byte_array: input.to_vec(),
            hex_representation,
            flags: self.config.flags.clone(),
            length: input.len(),
        }
    }
    
    fn analyze_characters(&self, input: &[u8]) -> Result<Vec<CharacterAnalysis>, Box<dyn std::error::Error>> {
        let mut analysis = Vec::new();
        
        for (pos, &byte) in input.iter().enumerate() {
            let char_repr = if byte >= 32 && byte <= 126 {
                format!("'{}'", byte as char)
            } else {
                format!("\\x{:02x}", byte)
            };
            
            // For now, we'll add placeholder analysis
            // TODO: This would need to access Rust's internal character dispatch
            analysis.push(CharacterAnalysis {
                position: pos,
                byte_value: byte,
                char_repr,
                char_type: "Unknown".to_string(), // TODO: Map to CharType
                parser_function: "unknown".to_string(), // TODO: Map to parser function
            });
            
            if self.config.interactive && pos < input.len() - 1 {
                println!("Press Enter to continue to next character...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
            }
        }
        
        Ok(analysis)
    }
    
    fn analyze_rust_tokenization(&self, input: &[u8]) -> Result<RustResults, Box<dyn std::error::Error>> {
        let flags = self.parse_flags(&self.config.flags)?;
        let mut state = SqliState::new(input, flags);
        
        // For now, we can only get the final result
        // TODO: Need to expose raw tokenization from libinjectionrs
        let fingerprint = state.get_fingerprint();
        let is_sqli = state.detect();
        
        // Convert tokens to our format
        let folded_tokens = state.tokens.iter().enumerate().map(|(i, token)| {
            TokenInfo {
                index: i,
                token_type: format!("{:?}", token.token_type),
                value: token.value_as_str().to_string(),
                position: token.pos,
                length: token.len,
                str_open: if token.str_open != 0 { Some(token.str_open as char) } else { None },
                str_close: if token.str_close != 0 { Some(token.str_close as char) } else { None },
            }
        }).collect();
        
        Ok(RustResults {
            raw_tokens: Vec::new(), // TODO: Need to capture raw tokens
            folded_tokens,
            fingerprint: fingerprint.as_str().to_string(),
            is_sqli,
        })
    }
    
    fn analyze_c_tokenization(&self, input: &[u8]) -> Result<CResults, Box<dyn std::error::Error>> {
        use std::process::Command;
        use std::ffi::OsStr;
        
        // Call the C debug harness
        let harness_path = "./c_harness/debug_harness";
        let input_str = String::from_utf8_lossy(input);
        
        let output = Command::new(harness_path)
            .arg(input_str.as_ref())
            .output()?;
            
        if !output.status.success() {
            return Err(format!("C harness failed: {}", String::from_utf8_lossy(&output.stderr)).into());
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_c_output(&output_str)
    }
    
    fn parse_c_output(&self, output: &str) -> Result<CResults, Box<dyn std::error::Error>> {
        let mut fingerprint = String::new();
        let mut is_sqli = false;
        let mut tokens = Vec::new();
        
        for line in output.lines() {
            if line.starts_with("FINGERPRINT: ") {
                fingerprint = line.strip_prefix("FINGERPRINT: ").unwrap_or("").to_string();
            } else if line.starts_with("IS_SQLI: ") {
                let sqli_str = line.strip_prefix("IS_SQLI: ").unwrap_or("0");
                is_sqli = sqli_str == "1";
            } else if line.starts_with("RAW_TOKEN_") {
                if let Some(token_info) = self.parse_c_token_line(line)? {
                    tokens.push(token_info);
                }
            }
        }
        
        Ok(CResults {
            fingerprint,
            is_sqli,
            tokens,
        })
    }
    
    fn parse_c_token_line(&self, line: &str) -> Result<Option<TokenInfo>, Box<dyn std::error::Error>> {
        // Parse lines like: RAW_TOKEN_0: NUMBER '0' 0 1
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None);
        }
        
        // Extract token index from RAW_TOKEN_N:
        let index_str = parts[0].strip_prefix("RAW_TOKEN_").and_then(|s| s.strip_suffix(":"));
        let index = if let Some(idx_str) = index_str {
            idx_str.parse().unwrap_or(0)
        } else {
            0
        };
        
        let token_type = parts[1].to_string();
        
        // Extract value from single quotes
        let mut value = String::new();
        let mut in_quotes = false;
        let mut quote_start = 0;
        for (i, part) in parts.iter().enumerate().skip(2) {
            if part.starts_with("'") {
                in_quotes = true;
                quote_start = i;
                value = part.strip_prefix("'").unwrap_or(part).to_string();
                if part.ends_with("'") && part.len() > 1 {
                    value = value.strip_suffix("'").unwrap_or(&value).to_string();
                    break;
                }
            } else if in_quotes {
                if part.ends_with("'") {
                    value.push(' ');
                    value.push_str(part.strip_suffix("'").unwrap_or(part));
                    break;
                } else {
                    value.push(' ');
                    value.push_str(part);
                }
            }
        }
        
        // Get position and length (last two numeric parts)
        let numeric_parts: Vec<usize> = parts.iter()
            .skip(quote_start + 1)
            .filter_map(|s| s.parse().ok())
            .collect();
            
        let (position, length) = if numeric_parts.len() >= 2 {
            (numeric_parts[numeric_parts.len() - 2], numeric_parts[numeric_parts.len() - 1])
        } else {
            (0, 0)
        };
        
        Ok(Some(TokenInfo {
            index,
            token_type,
            value,
            position,
            length,
            str_open: None,
            str_close: None,
        }))
    }
    
    fn parse_flags(&self, flags_str: &str) -> Result<SqliFlags, Box<dyn std::error::Error>> {
        // Parse flags string into SqliFlags
        match flags_str {
            "FLAG_NONE" => Ok(SqliFlags::FLAG_NONE),
            "FLAG_SQL_ANSI" => Ok(SqliFlags::FLAG_SQL_ANSI),
            "FLAG_SQL_MYSQL" => Ok(SqliFlags::FLAG_SQL_MYSQL),
            "FLAG_QUOTE_NONE" => Ok(SqliFlags::FLAG_QUOTE_NONE),
            "FLAG_QUOTE_SINGLE" => Ok(SqliFlags::FLAG_QUOTE_SINGLE),
            "FLAG_QUOTE_DOUBLE" => Ok(SqliFlags::FLAG_QUOTE_DOUBLE),
            _ => Err(format!("Unknown flag: {}", flags_str).into()),
        }
    }
}

struct RustResults {
    raw_tokens: Vec<TokenInfo>,
    folded_tokens: Vec<TokenInfo>,
    fingerprint: String,
    is_sqli: bool,
}

impl fmt::Display for TokenInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token {}: {} '{}' (pos={}, len={})", 
               self.index, self.token_type, self.value, self.position, self.length)
    }
}