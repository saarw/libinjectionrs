use crate::Fingerprint;
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod tokenizer;
mod blacklist;
mod sqli_data;

#[cfg(test)]
mod tests;

pub use tokenizer::{Token, TokenType, SqliTokenizer};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SqliFlags: u32 {
        const NONE = 0;
        const QUOTE_NONE = 1 << 0;
        const QUOTE_SINGLE = 1 << 1;
        const QUOTE_DOUBLE = 1 << 2;
        const SQL_ANSI = 1 << 3;
        const SQL_MYSQL = 1 << 4;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliResult {
    Safe,
    Injection { fingerprint: Fingerprint },
}

impl SqliResult {
    pub fn is_injection(&self) -> bool {
        matches!(self, SqliResult::Injection { .. })
    }
    
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        match self {
            SqliResult::Injection { fingerprint } => Some(fingerprint),
            SqliResult::Safe => None,
        }
    }
}

impl fmt::Display for SqliResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqliResult::Safe => write!(f, "Safe"),
            SqliResult::Injection { fingerprint } => {
                write!(f, "SQL Injection detected: {}", fingerprint)
            }
        }
    }
}

pub struct SqliDetector {
    flags: SqliFlags,
    lookup_fn: Option<Box<dyn Fn(&str) -> Option<TokenType>>>,
}

impl Default for SqliDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliDetector {
    pub fn new() -> Self {
        Self {
            flags: SqliFlags::NONE,
            lookup_fn: None,
        }
    }
    
    pub fn with_flags(mut self, flags: SqliFlags) -> Self {
        self.flags = flags;
        self
    }
    
    pub fn with_lookup<F>(mut self, lookup: F) -> Self
    where
        F: Fn(&str) -> Option<TokenType> + 'static,
    {
        self.lookup_fn = Some(Box::new(lookup));
        self
    }
    
    pub fn detect(&self, input: &[u8]) -> SqliResult {
        let mut state = SqliState::new(input, self.flags);
        
        if let Some(ref lookup) = self.lookup_fn {
            state.lookup_fn = Some(lookup.as_ref());
        }
        
        state.detect()
    }
    
    pub fn fingerprint(&self, input: &[u8]) -> Fingerprint {
        let mut state = SqliState::new(input, self.flags);
        
        if let Some(ref lookup) = self.lookup_fn {
            state.lookup_fn = Some(lookup.as_ref());
        }
        
        state.fingerprint()
    }
}

const LIBINJECTION_SQLI_MAX_TOKENS: usize = 5;
const LIBINJECTION_SQLI_TOKEN_SIZE: usize = 32;

struct SqliState<'a> {
    input: &'a [u8],
    flags: SqliFlags,
    pos: usize,
    
    tokens: Vec<Token>,
    current_token: Option<Token>,
    
    fingerprint: [u8; 8],
    reason: i32,
    
    stats_comment_ddw: i32,
    stats_comment_ddx: i32,
    stats_comment_c: i32,
    stats_comment_hash: i32,
    stats_folds: i32,
    stats_tokens: i32,
    
    lookup_fn: Option<&'a dyn Fn(&str) -> Option<TokenType>>,
}

impl<'a> SqliState<'a> {
    fn new(input: &'a [u8], flags: SqliFlags) -> Self {
        Self {
            input,
            flags,
            pos: 0,
            tokens: Vec::with_capacity(8),
            current_token: None,
            fingerprint: [0; 8],
            reason: 0,
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_c: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
            lookup_fn: None,
        }
    }
    
    fn detect(&mut self) -> SqliResult {
        if self.input.is_empty() {
            return SqliResult::Safe;
        }
        
        let contexts = if self.flags == SqliFlags::NONE {
            vec![
                SqliFlags::QUOTE_NONE | SqliFlags::SQL_ANSI,
                SqliFlags::QUOTE_SINGLE | SqliFlags::SQL_ANSI,
                SqliFlags::QUOTE_DOUBLE | SqliFlags::SQL_MYSQL,
            ]
        } else {
            vec![self.flags]
        };
        
        for context in contexts {
            self.reset(context);
            let fp = self.fingerprint();
            
            if self.is_sqli(&fp) {
                return SqliResult::Injection { fingerprint: fp };
            }
        }
        
        SqliResult::Safe
    }
    
    fn reset(&mut self, flags: SqliFlags) {
        self.flags = flags;
        self.pos = 0;
        self.tokens.clear();
        self.current_token = None;
        self.fingerprint = [0; 8];
        self.reason = 0;
        self.stats_comment_ddw = 0;
        self.stats_comment_ddx = 0;
        self.stats_comment_c = 0;
        self.stats_comment_hash = 0;
        self.stats_folds = 0;
        self.stats_tokens = 0;
    }
    
    fn fingerprint(&mut self) -> Fingerprint {
        self.tokenize();
        let token_count = self.fold_tokens();
        self.generate_fingerprint(token_count);
        Fingerprint::new(self.fingerprint)
    }
    
    fn tokenize(&mut self) {
        let mut tokenizer = SqliTokenizer::new(self.input, self.flags);
        
        while let Some(token) = tokenizer.next_token() {
            self.tokens.push(token);
            self.stats_tokens += 1;
            
            if self.tokens.len() >= LIBINJECTION_SQLI_MAX_TOKENS + 3 {
                break;
            }
        }
        
        self.stats_comment_c = tokenizer.stats_comment_c;
        self.stats_comment_ddw = tokenizer.stats_comment_ddw;
        self.stats_comment_ddx = tokenizer.stats_comment_ddx;
        self.stats_comment_hash = tokenizer.stats_comment_hash;
    }
    
    fn fold_tokens(&mut self) -> usize {
        let mut last_comment = Token::new();
        let mut pos = 0;
        let mut left = 0;
        let mut more = true;
        
        // Clear last comment
        last_comment.token_type = TokenType::None;
        
        // Ensure we have tokens to work with - start by getting first non-comment/paren/unary token
        let mut tokenizer = SqliTokenizer::new(self.input, self.flags);
        self.tokens.clear();
        
        // Skip initial comments, parens, and unary operators
        while more {
            if let Some(token) = tokenizer.next_token() {
                if token.token_type == TokenType::Comment ||
                   token.token_type == TokenType::LeftParenthesis ||
                   token.token_type == TokenType::SqlType ||
                   self.is_unary_op(&token) {
                    // Skip these tokens
                    continue;
                } else {
                    // Found a real token
                    self.tokens.push(token);
                    break;
                }
            } else {
                more = false;
            }
        }
        
        if !more {
            // If input was only comments, unary or (, then exit
            return 0;
        } else {
            // We have one token
            pos = 1;
        }
        
        loop {
            // Do we have all the max number of tokens? If so, do some special cases for 5 tokens
            if pos >= LIBINJECTION_SQLI_MAX_TOKENS {
                if self.check_special_5_token_patterns() {
                    if pos > LIBINJECTION_SQLI_MAX_TOKENS {
                        self.tokens[1] = self.tokens[LIBINJECTION_SQLI_MAX_TOKENS].clone();
                        pos = 2;
                        left = 0;
                    } else {
                        pos = 1;
                        left = 0;
                    }
                }
            }
            
            if !more || left >= LIBINJECTION_SQLI_MAX_TOKENS {
                left = pos;
                break;
            }
            
            // Get up to two tokens
            while more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 2 {
                if let Some(token) = tokenizer.next_token() {
                    if token.token_type == TokenType::Comment {
                        last_comment = token;
                    } else {
                        last_comment.token_type = TokenType::None;
                        if pos < self.tokens.len() {
                            self.tokens[pos] = token;
                        } else {
                            self.tokens.push(token);
                        }
                        pos += 1;
                    }
                } else {
                    more = false;
                }
            }
            
            // Did we get 2 tokens? If not then we are done
            if pos - left < 2 {
                left = pos;
                continue;
            }
            
            // Try 2-token folding rules
            if self.try_fold_two_tokens(left, &mut pos, &mut left) {
                continue;
            }
            
            // Get one more token for 3-token rules
            while more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && pos - left < 3 {
                if let Some(token) = tokenizer.next_token() {
                    if token.token_type == TokenType::Comment {
                        last_comment = token;
                    } else {
                        last_comment.token_type = TokenType::None;
                        if pos < self.tokens.len() {
                            self.tokens[pos] = token;
                        } else {
                            self.tokens.push(token);
                        }
                        pos += 1;
                    }
                } else {
                    more = false;
                }
            }
            
            // Do we have three tokens? If not then we are done
            if pos - left < 3 {
                left = pos;
                continue;
            }
            
            // Try 3-token folding rules
            if self.try_fold_three_tokens(left, &mut pos, &mut left) {
                continue;
            }
            
            // No folding -- assume left-most token is good, now use the existing 2 tokens --
            // do not get another
            left += 1;
        }
        
        // If we have 4 or less tokens, and we had a comment token at the end, add it back
        if left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.token_type == TokenType::Comment {
            if left < self.tokens.len() {
                self.tokens[left] = last_comment;
            } else {
                self.tokens.push(last_comment);
            }
            left += 1;
        }
        
        // Sometimes we grab a 6th token to help determine the type of token 5.
        if left > LIBINJECTION_SQLI_MAX_TOKENS {
            left = LIBINJECTION_SQLI_MAX_TOKENS;
        }
        
        self.tokens.truncate(left);
        left
    }
    
    fn is_unary_op(&self, token: &Token) -> bool {
        if token.token_type != TokenType::Operator {
            return false;
        }
        
        let val = token.value_as_str();
        match val.len() {
            1 => matches!(val.chars().next(), Some('+' | '-' | '!' | '~')),
            2 => val == "!!",
            3 => val.to_ascii_uppercase() == "NOT",
            _ => false,
        }
    }
    
    fn is_arithmetic_op(&self, token: &Token) -> bool {
        if token.token_type != TokenType::Operator {
            return false;
        }
        
        let ch = token.value_as_str().chars().next().unwrap_or('\0');
        matches!(ch, '+' | '-' | '*' | '/' | '%' | '^')
    }
    
    fn check_special_5_token_patterns(&self) -> bool {
        if self.tokens.len() < 5 {
            return false;
        }
        
        let t = &self.tokens;
        
        // Pattern: number operator ( number )
        (t[0].token_type == TokenType::Number &&
         (t[1].token_type == TokenType::Operator || t[1].token_type == TokenType::Comma) &&
         t[2].token_type == TokenType::LeftParenthesis &&
         t[3].token_type == TokenType::Number &&
         t[4].token_type == TokenType::RightParenthesis) ||
        
        // Pattern: bareword operator ( bareword|number )
        (t[0].token_type == TokenType::Bareword &&
         t[1].token_type == TokenType::Operator &&
         t[2].token_type == TokenType::LeftParenthesis &&
         (t[3].token_type == TokenType::Bareword || t[3].token_type == TokenType::Number) &&
         t[4].token_type == TokenType::RightParenthesis) ||
        
        // Pattern: number ) , ( number
        (t[0].token_type == TokenType::Number &&
         t[1].token_type == TokenType::RightParenthesis &&
         t[2].token_type == TokenType::Comma &&
         t[3].token_type == TokenType::LeftParenthesis &&
         t[4].token_type == TokenType::Number) ||
        
        // Pattern: bareword ) operator ( bareword
        (t[0].token_type == TokenType::Bareword &&
         t[1].token_type == TokenType::RightParenthesis &&
         t[2].token_type == TokenType::Operator &&
         t[3].token_type == TokenType::LeftParenthesis &&
         t[4].token_type == TokenType::Bareword)
    }
    
    fn try_fold_two_tokens(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        if left + 1 >= self.tokens.len() {
            return false;
        }
        
        let t_left = self.tokens[left].token_type;
        let t_right = self.tokens[left + 1].token_type;
        
        // FOLD: "ss" -> "s" (string concatenation)
        if t_left == TokenType::String && t_right == TokenType::String {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // FOLD: ";;" -> ";" (duplicate semicolons)  
        if t_left == TokenType::Semicolon && t_right == TokenType::Semicolon {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // FOLD: operator + unary_op -> operator
        if (t_left == TokenType::Operator || t_left == TokenType::LogicOperator) &&
           (self.is_unary_op(&self.tokens[left + 1]) || t_right == TokenType::SqlType) {
            *pos -= 1;
            self.stats_folds += 1;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: ( + unary_op -> (
        if t_left == TokenType::LeftParenthesis && self.is_unary_op(&self.tokens[left + 1]) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            return true;
        }
        
        // Word merging - just check if it would merge
        if self.can_merge_words(left) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            return true;
        }
        
        // Handle TSQL IF after semicolon
        if t_left == TokenType::Semicolon && t_right == TokenType::Function {
            let val = self.tokens[left + 1].value_as_str().to_ascii_uppercase();
            if val == "IF" {
                self.tokens[left + 1].token_type = TokenType::Tsql;
                return true;
            }
        }
        
        false
    }
    
    fn try_fold_three_tokens(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        if left + 2 >= self.tokens.len() {
            return false;
        }
        
        let types = [
            self.tokens[left].token_type,
            self.tokens[left + 1].token_type,
            self.tokens[left + 2].token_type,
        ];
        
        // FOLD: number operator number -> number
        if types[0] == TokenType::Number && 
           types[1] == TokenType::Operator && 
           types[2] == TokenType::Number {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: operator X operator -> operator (where X != leftparen)
        if types[0] == TokenType::Operator && 
           types[1] != TokenType::LeftParenthesis && 
           types[2] == TokenType::Operator {
            *left_ptr = 0;
            *pos -= 2;
            return true;
        }
        
        false
    }
    
    fn can_merge_words(&self, left: usize) -> bool {
        if left + 1 >= self.tokens.len() {
            return false;
        }
        
        let a_type = self.tokens[left].token_type;
        let b_type = self.tokens[left + 1].token_type;
        
        // Check if both tokens are mergeable types
        let mergeable_types = [
            TokenType::Keyword, TokenType::Bareword, TokenType::Operator,
            TokenType::Union, TokenType::Function, TokenType::Expression,
            TokenType::Tsql, TokenType::SqlType, TokenType::LogicOperator
        ];
        
        if !mergeable_types.contains(&a_type) || !mergeable_types.contains(&b_type) {
            return false;
        }
        
        let a_val = self.tokens[left].value_as_str();
        let b_val = self.tokens[left + 1].value_as_str();
        
        if a_val.len() + b_val.len() + 1 >= 32 {
            return false;
        }
        
        let merged = format!("{} {}", a_val, b_val);
        let lookup_result = sqli_data::lookup_word(&merged.to_ascii_uppercase());
        
        lookup_result != TokenType::Bareword
    }
    
    fn generate_fingerprint(&mut self, token_count: usize) {
        let mut fp_idx = 0;
        
        for i in 0..token_count.min(LIBINJECTION_SQLI_MAX_TOKENS) {
            if fp_idx >= 8 || i >= self.tokens.len() {
                break;
            }
            
            let token = &self.tokens[i];
            let ch = match token.token_type {
                TokenType::Keyword => b'k',
                TokenType::Union => b'U',
                TokenType::Group => b'B',
                TokenType::Expression => b'E',
                TokenType::SqlType => b't',
                TokenType::Function => b'f',
                TokenType::Bareword => b'n',
                TokenType::Number => b'1',
                TokenType::Variable => b'v',
                TokenType::String => b's',
                TokenType::Operator => b'o',
                TokenType::LogicOperator => b'&',
                TokenType::Comment => b'c',
                TokenType::Collate => b'A',
                TokenType::LeftParenthesis => b'(',
                TokenType::RightParenthesis => b')',
                TokenType::LeftBrace => b'{',
                TokenType::RightBrace => b'}',
                TokenType::Dot => b'.',
                TokenType::Comma => b',',
                TokenType::Colon => b':',
                TokenType::Semicolon => b';',
                TokenType::Tsql => b'T',
                TokenType::Unknown => b'?',
                TokenType::Evil => b'X',
                TokenType::Fingerprint => b'F',
                TokenType::Backslash => b'\\',
                _ => b'?',
            };
            
            self.fingerprint[fp_idx] = ch;
            fp_idx += 1;
        }
        
        // Null terminate the fingerprint
        while fp_idx < 8 {
            self.fingerprint[fp_idx] = 0;
            fp_idx += 1;
        }
    }
    
    fn is_sqli(&self, fingerprint: &Fingerprint) -> bool {
        blacklist::is_blacklisted(fingerprint.as_str())
    }
}

pub fn detect_sqli(input: &[u8]) -> SqliResult {
    SqliDetector::new().detect(input)
}