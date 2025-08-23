use bitflags::bitflags;
use core::fmt;


use crate::Fingerprint;

mod sqli_data;
mod sqli_tokenizer;
mod fingerprint_data;
#[cfg(test)]
mod tests;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SqliFlags: u32 {
        const NONE = 0;
        const QUOTE_NONE = 1 << 0;
        const QUOTE_SINGLE = 1 << 1;
        const QUOTE_DOUBLE = 1 << 2;
        const ANSI = 1 << 3;
        const MYSQL = 1 << 4;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    None,
    Keyword,
    Union,
    Group,
    Expression,
    SqlType,
    Function,
    Bareword,
    Variable,
    Number,
    String,
    Operator,
    Logic,
    Comment,
    Collate,
    LeftParenthesis,
    RightParenthesis,
    LeftBrace,
    RightBrace,
    Comma,
    Semicolon,
    Backslash,
    Dot,
    Colon,
    Tsql,
    Unknown,
    Evil,
    Fingerprint,
}

impl TokenType {
    pub fn to_char(&self) -> char {
        match self {
            TokenType::None => '0',
            TokenType::Keyword => 'k',
            TokenType::Union => 'U',
            TokenType::Group => 'B',
            TokenType::Expression => 'E',
            TokenType::SqlType => 't',
            TokenType::Function => 'f',
            TokenType::Bareword => 'n',
            TokenType::Variable => 'v',
            TokenType::Number => '1',
            TokenType::String => 's',
            TokenType::Operator => 'o',
            TokenType::Logic => '&',
            TokenType::Comment => 'c',
            TokenType::Collate => 'A',
            TokenType::LeftParenthesis => '(',
            TokenType::RightParenthesis => ')',
            TokenType::LeftBrace => '{',
            TokenType::RightBrace => '}',
            TokenType::Comma => ',',
            TokenType::Semicolon => ';',
            TokenType::Backslash => '\\',
            TokenType::Dot => '.',
            TokenType::Colon => ':',
            TokenType::Tsql => 'T',
            TokenType::Unknown => '?',
            TokenType::Evil => 'X',
            TokenType::Fingerprint => 'F',
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => TokenType::None,
            b'k' => TokenType::Keyword,
            b'U' => TokenType::Union,
            b'B' => TokenType::Group,
            b'E' => TokenType::Expression,
            b't' => TokenType::SqlType,
            b'f' => TokenType::Function,
            b'n' => TokenType::Bareword,
            b'v' => TokenType::Variable,
            b'1' => TokenType::Number,
            b's' => TokenType::String,
            b'o' => TokenType::Operator,
            b'&' => TokenType::Logic,
            b'c' => TokenType::Comment,
            b'A' => TokenType::Collate,
            b'(' => TokenType::LeftParenthesis,
            b')' => TokenType::RightParenthesis,
            b'{' => TokenType::LeftBrace,
            b'}' => TokenType::RightBrace,
            b',' => TokenType::Comma,
            b';' => TokenType::Semicolon,
            b'\\' => TokenType::Backslash,
            b'.' => TokenType::Dot,
            b':' => TokenType::Colon,
            b'T' => TokenType::Tsql,
            b'X' => TokenType::Evil,
            b'F' => TokenType::Fingerprint,
            _ => TokenType::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub pos: usize,
    pub len: usize,
    pub value: [u8; 32], // Fixed size like C version
    pub value_len: usize,
    pub str_open: Option<u8>,
    pub str_close: Option<u8>,
    pub count: i32,
}

impl Token {
    pub fn new(token_type: u8, pos: usize, value: &[u8]) -> Self {
        let mut token = Self {
            token_type: TokenType::from_byte(token_type),
            pos,
            len: value.len(),
            value: [0; 32],
            value_len: value.len().min(31),
            str_open: None,
            str_close: None,
            count: 0,
        };
        
        let copy_len = value.len().min(31);
        token.value[..copy_len].copy_from_slice(&value[..copy_len]);
        token
    }
    
    pub fn new_char(token_type: u8, pos: usize, ch: u8) -> Self {
        let mut token = Self {
            token_type: TokenType::from_byte(token_type),
            pos,
            len: 1,
            value: [0; 32],
            value_len: 1,
            str_open: None,
            str_close: None,
            count: 0,
        };
        
        token.value[0] = ch;
        token
    }
    
    pub fn value_slice(&self) -> &[u8] {
        &self.value[..self.value_len]
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

    pub fn detect(&self, input: &[u8]) -> SqliResult {
        if input.is_empty() {
            return SqliResult::Safe;
        }
        
        // Test input "as-is" with ANSI flags
        let mut state = SqliState::new(input, SqliFlags::NONE | SqliFlags::ANSI);
        if let Some(fingerprint) = self.detect_with_context(&mut state, SqliFlags::NONE) {
            return SqliResult::Injection { fingerprint };
        }
        
        // Try MySQL mode if ANSI didn't match
        let mut state = SqliState::new(input, SqliFlags::NONE | SqliFlags::MYSQL);
        if let Some(fingerprint) = self.detect_with_context(&mut state, SqliFlags::NONE) {
            return SqliResult::Injection { fingerprint };
        }
        
        // If input has single quotes, test with single quote context
        if input.iter().any(|&ch| ch == b'\'') {
            let mut state = SqliState::new(input, SqliFlags::QUOTE_SINGLE | SqliFlags::ANSI);
            if let Some(fingerprint) = self.detect_with_context(&mut state, SqliFlags::QUOTE_SINGLE) {
                return SqliResult::Injection { fingerprint };
            }
            
            // Try MySQL mode with single quotes
            let mut state = SqliState::new(input, SqliFlags::QUOTE_SINGLE | SqliFlags::MYSQL);
            if let Some(fingerprint) = self.detect_with_context(&mut state, SqliFlags::QUOTE_SINGLE) {
                return SqliResult::Injection { fingerprint };
            }
        }
        
        // If input has double quotes, test with double quote context
        if input.iter().any(|&ch| ch == b'"') {
            let mut state = SqliState::new(input, SqliFlags::QUOTE_DOUBLE | SqliFlags::MYSQL);
            if let Some(fingerprint) = self.detect_with_context(&mut state, SqliFlags::QUOTE_DOUBLE) {
                return SqliResult::Injection { fingerprint };
            }
        }

        SqliResult::Safe
    }

    fn detect_with_context(&self, state: &mut SqliState, context: SqliFlags) -> Option<Fingerprint> {
        // Handle quote context like C implementation
        if context.contains(SqliFlags::QUOTE_SINGLE) {
            // Prepend single quote to simulate string context
            let mut quoted_input = Vec::with_capacity(state.input.len() + 1);
            quoted_input.push(b'\'');
            quoted_input.extend_from_slice(state.input);
            let mut quoted_state = SqliState::new(&quoted_input, state.flags);
            quoted_state.tokenize();
            quoted_state.fold();
            if quoted_state.check_fingerprint() {
                return Some(quoted_state.get_fingerprint());
            }
        } else if context.contains(SqliFlags::QUOTE_DOUBLE) {
            // Prepend double quote to simulate string context
            let mut quoted_input = Vec::with_capacity(state.input.len() + 1);
            quoted_input.push(b'"');
            quoted_input.extend_from_slice(state.input);
            let mut quoted_state = SqliState::new(&quoted_input, state.flags);
            quoted_state.tokenize();
            quoted_state.fold();
            if quoted_state.check_fingerprint() {
                return Some(quoted_state.get_fingerprint());
            }
        } else {
            // Regular context
            state.tokenize();
            state.fold();
            if state.check_fingerprint() {
                return Some(state.get_fingerprint());
            }
        }
        
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
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

pub struct SqliState<'a> {
    pub input: &'a [u8],
    pub flags: SqliFlags,
    pub pos: usize,
    pub current: Token,
    pub tokens: Vec<Token>,
    pub fingerprint: [u8; 8],
    pub stats_comment_ddw: u32,
    pub stats_comment_ddx: u32,
    pub stats_comment_c: u32,
    pub stats_comment_hash: u32,
    pub stats_folds: u32,
    pub stats_tokens: u32,
}

impl<'a> SqliState<'a> {
    pub fn new(input: &'a [u8], flags: SqliFlags) -> Self {
        Self {
            input,
            flags,
            pos: 0,
            current: Token::new(0, 0, &[]),
            tokens: Vec::with_capacity(8),
            fingerprint: [0; 8],
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_c: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
        }
    }

    pub fn tokenize(&mut self) {
        use crate::sqli::sqli_data::CHAR_PARSE_MAP;
        
        while self.pos < self.input.len() && self.tokens.len() < 5 {
            self.skip_whitespace();
            
            if self.pos >= self.input.len() {
                break;
            }
            
            let ch = self.input[self.pos];
            let parse_fn = CHAR_PARSE_MAP[ch as usize];
            
            let new_pos = parse_fn(self);
            
            // Check if a token was created
            if self.current.token_type != TokenType::None {
                self.tokens.push(self.current.clone());
                self.stats_tokens += 1;
            }
            
            self.pos = new_pos;
            
            // Reset current token
            self.current = Token::new(0, 0, &[]);
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && 
              sqli_tokenizer::char_is_white(self.input[self.pos]) {
            self.pos += 1;
        }
    }

    pub fn fold(&mut self) {
        let mut last_comment: Option<Token> = None;
        let mut pos = 0;
        let mut left = 0;
        let max_tokens = 5; // LIBINJECTION_SQLI_MAX_TOKENS
        
        // Skip all initial comments, left parens and unary operators
        let mut more = true;
        while more && pos < self.tokens.len() {
            let current_token = &self.tokens[pos];
            if !(current_token.token_type == TokenType::Comment ||
                 current_token.token_type == TokenType::LeftParenthesis ||
                 current_token.token_type == TokenType::SqlType ||
                 self.is_unary_op(current_token)) {
                break;
            }
            pos += 1;
        }
        
        if pos >= self.tokens.len() {
            // If input was only comments, unary or (, then exit
            self.tokens.clear();
            return;
        } else {
            // Move the first non-skipped token to position 0
            if pos > 0 {
                self.tokens[0] = self.tokens[pos].clone();
            }
            pos = 1;
        }
        
        // Main folding loop - this is where the complex logic goes
        loop {
            // Check if we have max tokens - special 5-token cases
            if pos >= max_tokens {
                // Handle special 5-token folding cases from C implementation
                if self.handle_five_token_cases(&mut pos, &mut left) {
                    continue;
                }
            }
            
            if pos >= self.tokens.len() || left >= max_tokens {
                left = pos;
                break;
            }
            
            // Get up to two more tokens
            while more && pos <= max_tokens && (pos - left) < 2 && pos < self.tokens.len() {
                let current_token = &self.tokens[pos];
                if current_token.token_type == TokenType::Comment {
                    last_comment = Some(current_token.clone());
                } else {
                    pos += 1;
                }
                
                if pos >= self.tokens.len() {
                    more = false;
                }
            }
            
            // Did we get 2 tokens? If not, we're done
            if pos - left < 2 {
                left = pos;
                break;
            }
            
            // Apply folding rules
            if self.apply_folding_rules(left, pos, &mut pos, &mut left) {
                continue;
            }
            
            // No folding - move to next token
            left += 1;
        }
        
        // Add back last comment if we have room
        if left < max_tokens {
            if let Some(comment) = last_comment {
                if left < self.tokens.len() {
                    self.tokens[left] = comment;
                    left += 1;
                }
            }
        }
        
        // Truncate tokens to final length
        if left > max_tokens {
            left = max_tokens;
        }
        self.tokens.truncate(left);
        
        // Convert first token to Expression if it's a statement keyword  
        if !self.tokens.is_empty() {
            let is_statement_kw = if let Some(first_token) = self.tokens.get(0) {
                first_token.token_type == TokenType::Keyword && self.is_statement_keyword(first_token)
            } else {
                false
            };
            
            if is_statement_kw {
                if let Some(first_token) = self.tokens.get_mut(0) {
                    first_token.token_type = TokenType::Expression;
                }
            }
        }
    }
    
    fn is_unary_op(&self, token: &Token) -> bool {
        if token.token_type != TokenType::Operator {
            return false;
        }
        
        let value = std::str::from_utf8(token.value_slice()).unwrap_or("");
        matches!(value, "+" | "-" | "!" | "~" | "NOT")
    }
    
    fn is_statement_keyword(&self, token: &Token) -> bool {
        let value = std::str::from_utf8(token.value_slice()).unwrap_or("");
        let upper_value = value.to_uppercase();
        matches!(upper_value.as_str(), 
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER" |
            "SHOW" | "DESCRIBE" | "EXPLAIN" | "WITH" | "MERGE" | "UPSERT"
        )
    }
    
    fn handle_five_token_cases(&mut self, pos: &mut usize, left: &mut usize) -> bool {
        if self.tokens.len() < 5 {
            return false;
        }
        
        // Check the specific 5-token patterns from C implementation
        let pattern_matches = 
            (self.tokens[0].token_type == TokenType::Number &&
             (self.tokens[1].token_type == TokenType::Operator ||
              self.tokens[1].token_type == TokenType::Comma) &&
             self.tokens[2].token_type == TokenType::LeftParenthesis &&
             self.tokens[3].token_type == TokenType::Number &&
             self.tokens[4].token_type == TokenType::RightParenthesis) ||
            (self.tokens[0].token_type == TokenType::Bareword &&
             self.tokens[1].token_type == TokenType::Operator &&
             self.tokens[2].token_type == TokenType::LeftParenthesis &&
             (self.tokens[3].token_type == TokenType::Bareword ||
              self.tokens[3].token_type == TokenType::Number) &&
             self.tokens[4].token_type == TokenType::RightParenthesis);
             
        if pattern_matches {
            if *pos > 5 {
                // Shift tokens down
                if self.tokens.len() > 5 {
                    self.tokens[1] = self.tokens[5].clone();
                }
                *pos = 2;
                *left = 0;
            } else {
                *pos = 1;
                *left = 0;
            }
            return true;
        }
        
        false
    }
    
    fn apply_folding_rules(&mut self, left: usize, _current_pos: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        if left + 1 >= self.tokens.len() {
            return false;
        }
        
        let left_token = &self.tokens[left];
        let right_token = &self.tokens[left + 1];
        
        // Rule: "ss" -> "s" (string folding)
        if left_token.token_type == TokenType::String && right_token.token_type == TokenType::String {
            self.tokens.remove(left + 1);
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // Rule: ";;" -> ";" (semicolon folding)
        if left_token.token_type == TokenType::Semicolon && right_token.token_type == TokenType::Semicolon {
            self.tokens.remove(left + 1);
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // Rule: operator + unary -> remove unary
        if (left_token.token_type == TokenType::Operator || left_token.token_type == TokenType::Logic) &&
           (self.is_unary_op(right_token) || right_token.token_type == TokenType::SqlType) {
            self.tokens.remove(left + 1);
            *pos -= 1;
            *left_ptr = 0;
            self.stats_folds += 1;
            return true;
        }
        
        // Rule: "(" + unary -> remove unary
        if left_token.token_type == TokenType::LeftParenthesis && self.is_unary_op(right_token) {
            self.tokens.remove(left + 1);
            *pos -= 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            self.stats_folds += 1;
            return true;
        }
        
        // Additional folding rules would go here...
        // This is a simplified version - the full C implementation has many more rules
        
        false
    }

    pub fn check_fingerprint(&mut self) -> bool {
        // Generate fingerprint from tokens (matches C implementation exactly)
        let mut fingerprint_len = 0;
        for (i, token) in self.tokens.iter().enumerate() {
            if i >= 8 {
                break;
            }
            self.fingerprint[i] = token.token_type.to_char() as u8;
            fingerprint_len = i + 1;
        }
        
        // Pad with null bytes
        for i in fingerprint_len..8 {
            self.fingerprint[i] = 0;
        }
        
        // Convert to string and then to v1 format like C implementation
        let fingerprint_str = std::str::from_utf8(&self.fingerprint[..fingerprint_len])
            .unwrap_or("");
        
        if fingerprint_str.is_empty() {
            return false;
        }
        
        // Convert to v1 format and check against compiled fingerprints
        let v1_fingerprint = fingerprint_data::to_v1_format(fingerprint_str);
        
        // This matches: is_keyword(fp2, len + 1) == TYPE_FINGERPRINT
        fingerprint_data::is_fingerprint_match(&v1_fingerprint)
    }

    pub fn get_fingerprint(&self) -> Fingerprint {
        Fingerprint::new(self.fingerprint)
    }
}

pub fn detect_sqli(input: &[u8]) -> SqliResult {
    SqliDetector::new().detect(input)
}