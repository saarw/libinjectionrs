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

#[derive(Debug, Clone, Copy)]
pub struct Token {
    pub pos: usize,
    pub len: usize,
    pub count: i32,              // CRITICAL: Moved to match C memory layout
    pub token_type: char,        // CRITICAL: Use char to match C exactly
    pub str_open: char,          // CRITICAL: Use char with CHAR_NULL sentinel
    pub str_close: char,         // CRITICAL: Use char with CHAR_NULL sentinel
    pub val: [u8; 32],           // Fixed char val[32] array, null-terminated
}

const CHAR_NULL: char = '\0';

impl Token {
    pub fn new() -> Self {
        Self {
            pos: 0,
            len: 0,
            count: 0,
            token_type: CHAR_NULL,
            str_open: CHAR_NULL,
            str_close: CHAR_NULL,
            val: [0; 32],
        }
    }
    
    pub fn clear(&mut self) {
        self.pos = 0;
        self.len = 0;
        self.count = 0;
        self.token_type = CHAR_NULL;
        self.str_open = CHAR_NULL;
        self.str_close = CHAR_NULL;
        self.val = [0; 32];
    }
    
    pub fn assign_char(&mut self, token_type: char, pos: usize, ch: char) {
        self.token_type = token_type;
        self.pos = pos;
        self.len = 1;
        self.val[0] = ch as u8;
        self.val[1] = 0; // null terminate
        self.count = 0;
        self.str_open = CHAR_NULL;
        self.str_close = CHAR_NULL;
    }
    
    pub fn assign(&mut self, token_type: char, pos: usize, len: usize, value: &[u8]) {
        self.token_type = token_type;
        self.pos = pos;
        self.len = len;
        let copy_len = value.len().min(31);
        self.val[..copy_len].copy_from_slice(&value[..copy_len]);
        self.val[copy_len] = 0; // null terminate
        self.count = 0;
        self.str_open = CHAR_NULL;
        self.str_close = CHAR_NULL;
    }
    
    pub fn copy_from(&mut self, other: &Token) {
        self.pos = other.pos;
        self.len = other.len;
        self.token_type = other.token_type;
        self.count = other.count;
        self.str_open = other.str_open;
        self.str_close = other.str_close;
        self.val = other.val;
    }
    
    pub fn get_token_type(&self) -> TokenType {
        TokenType::from_byte(self.token_type as u8)
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

    /// Matches C's libinjection_is_sqli exactly
    pub fn detect(&self, input: &[u8]) -> SqliResult {
        if input.is_empty() {
            return SqliResult::Safe;
        }
        
        // Test input "as-is" with ANSI flags (matches C exactly)
        let mut state = SqliState::new(input, SqliFlags::NONE | SqliFlags::ANSI);
        self.fingerprint(&mut state);
        if self.lookup_fingerprint(&mut state) {
            let fp = state.get_fingerprint();
            return SqliResult::Injection { fingerprint: fp };
        }
        
        let should_reparse = self.reparse_as_mysql(&state);
        if should_reparse {
            let mut state = SqliState::new(input, SqliFlags::NONE | SqliFlags::MYSQL);
            self.fingerprint(&mut state);
            if self.lookup_fingerprint(&mut state) {
                let fp = state.get_fingerprint();
                return SqliResult::Injection { fingerprint: fp };
            }
        }
        
        // If input has single quotes, test with single quote context
        if input.contains(&b'\'') {
            let mut state = SqliState::new(input, SqliFlags::QUOTE_SINGLE | SqliFlags::ANSI);
            self.fingerprint(&mut state);
            if self.lookup_fingerprint(&mut state) {
                let fp = state.get_fingerprint();
                return SqliResult::Injection { fingerprint: fp };
            }
            
            let should_reparse = self.reparse_as_mysql(&state);
            if should_reparse {
                let mut state = SqliState::new(input, SqliFlags::QUOTE_SINGLE | SqliFlags::MYSQL);
                self.fingerprint(&mut state);
                if self.lookup_fingerprint(&mut state) {
                    let fp = state.get_fingerprint();
                    return SqliResult::Injection { fingerprint: fp };
                }
            }
        }
        
        // If input has double quotes, test with double quote context
        if input.contains(&b'"') {
            let mut state = SqliState::new(input, SqliFlags::QUOTE_DOUBLE | SqliFlags::MYSQL);
            self.fingerprint(&mut state);
            if self.lookup_fingerprint(&mut state) {
                let fp = state.get_fingerprint();
                return SqliResult::Injection { fingerprint: fp };
            }
        }
        
        SqliResult::Safe
    }
    
    /// Matches C's reparse_as_mysql function exactly
    fn reparse_as_mysql(&self, state: &SqliState) -> bool {
        state.stats_comment_ddx > 0 || state.stats_comment_hash > 0
    }

    /// Matches C's libinjection_sqli_fingerprint exactly
    fn fingerprint(&self, state: &mut SqliState) {
        // Reset state with current flags (matches C exactly)
        state.reset(state.flags);
        
        // Do the folding (matches C's libinjection_sqli_fold)
        let tlen = state.fold();
        
        // Check for magic PHP backquote comment (matches C logic exactly)
        if tlen > 2 && 
           state.tokenvec[tlen - 1].token_type == 'n' &&
           state.tokenvec[tlen - 1].str_open == '`' &&
           state.tokenvec[tlen - 1].len == 0 &&
           state.tokenvec[tlen - 1].str_close == CHAR_NULL {
            state.tokenvec[tlen - 1].token_type = 'c';
        }
        
        // Build fingerprint from tokens
        for i in 0..tlen {
            state.fingerprint[i] = state.tokenvec[i].token_type as u8;
        }
        
        // Null terminate fingerprint
        state.fingerprint[tlen] = 0;
        
        // Check for 'X' (TYPE_EVIL) in pattern
        if state.fingerprint[..tlen].contains(&(b'X')) {
            // Clear all tokens and set to evil
            state.fingerprint = [0; 8];
            for token in &mut state.tokenvec {
                token.clear();
            }
            state.fingerprint[0] = b'X';
            state.tokenvec[0].assign_char('X', 0, 'X');
            state.tokenvec[1].token_type = CHAR_NULL;
        }
        
        // Fingerprint has been set in state
        // C version returns fingerprint as convenience, but we don't need to
    }
    
    /// Matches C's lookup behavior exactly
    fn lookup_fingerprint(&self, state: &mut SqliState) -> bool {
        state.check_fingerprint()
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
    /// input string, not modified 
    pub s: &'a [u8],
    /// input length
    pub slen: usize,
    /// flags
    pub flags: SqliFlags,
    /// position in string during tokenization
    pub pos: usize,
    /// token array (matches C exactly)
    pub tokenvec: [Token; 8], // MAX_TOKENS + extra for lookahead
    /// pointer to current token
    pub current: *mut Token,
    /// fingerprint pattern
    pub fingerprint: [u8; 8],
    /// stats
    pub stats_comment_ddw: u32,
    pub stats_comment_ddx: u32, 
    pub stats_comment_c: u32,
    pub stats_comment_hash: u32,
    pub stats_folds: u32,
    pub stats_tokens: u32,
    /// for debugging
    pub reason: u32,
}

impl<'a> SqliState<'a> {
    pub fn new(s: &'a [u8], flags: SqliFlags) -> Self {
        let mut state = Self {
            s,
            slen: s.len(),
            flags: if flags.is_empty() { SqliFlags::QUOTE_NONE | SqliFlags::ANSI } else { flags },
            pos: 0,
            tokenvec: [Token::new(); 8],
            current: std::ptr::null_mut(),
            fingerprint: [0; 8],
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_c: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
            reason: 0,
        };
        // Set current to point to first token
        state.current = &mut state.tokenvec[0] as *mut Token;
        state
    }
    
    pub fn reset(&mut self, flags: SqliFlags) {
        let flags = if flags.is_empty() { SqliFlags::QUOTE_NONE | SqliFlags::ANSI } else { flags };
        self.flags = flags;
        self.pos = 0;
        self.tokenvec = [Token::new(); 8];
        self.current = &mut self.tokenvec[0] as *mut Token;
        self.fingerprint = [0; 8];
        self.stats_comment_ddw = 0;
        self.stats_comment_ddx = 0;
        self.stats_comment_c = 0;
        self.stats_comment_hash = 0;
        self.stats_folds = 0;
        self.stats_tokens = 0;
        self.reason = 0;
    }
    
    pub fn current_token(&mut self) -> &mut Token {
        unsafe { &mut *self.current }
    }

    /// Get next token - matches C's libinjection_sqli_tokenize exactly
    pub fn tokenize(&mut self) -> bool {
        use crate::sqli::sqli_data::CHAR_PARSE_MAP;
        
        if self.slen == 0 {
            return false;
        }
        
        // Clear current token (matches C st_clear)
        unsafe {
            (*self.current).clear();
        }
        
        // Handle quote context at beginning of string (matches C logic exactly)
        if self.pos == 0 && self.flags.intersects(SqliFlags::QUOTE_SINGLE | SqliFlags::QUOTE_DOUBLE) {
            let delim = if self.flags.contains(SqliFlags::QUOTE_SINGLE) { '\'' } else { '"' };
            self.pos = self.parse_string_core(0, delim);
            self.stats_tokens += 1;
            return true;
        }
        
        while self.pos < self.slen {
            let ch = self.s[self.pos] as usize;
            let parse_fn = CHAR_PARSE_MAP[ch];
            
            self.pos = parse_fn(self);
            
            // Check if a token was created (matches C logic)
            let current_type = unsafe { (*self.current).token_type };
            if current_type != CHAR_NULL {
                self.stats_tokens += 1;
                return true;
            }
        }
        
        false
    }
    
    fn parse_string_core(&mut self, pos: usize, delim: char) -> usize {
        // Matches C's parse_string_core exactly with proper FLAG_QUOTE handling
        use crate::sqli::sqli_tokenizer::parse_string_core;
        parse_string_core(self, delim, if pos == 0 { 0 } else { 1 })
    }


    /// Implements C's libinjection_sqli_fold exactly
    pub fn fold(&mut self) -> usize {
        const MAX_TOKENS: usize = 5;
        
        let mut last_comment = Token::new();
        let mut pos: usize = 0;
        let mut left: usize = 0;
        let mut more = true;
        
        // Skip all initial comments, left-parens and unary operators
        self.current = &mut self.tokenvec[0] as *mut Token;
        while more {
            more = self.tokenize();
            let current_token = unsafe { &*self.current };
            if !(current_token.token_type == 'c' ||
                 current_token.token_type == '(' ||
                 current_token.token_type == 't' ||
                 self.is_unary_op(current_token)) {
                break;
            }
        }
        
        if !more {
            return 0; // Only comments, unary or (, then exit
        } else {
            pos += 1; // it's some other token
        }
        
        // Main folding loop (matches C exactly)
        loop {
            // Handle 5-token special cases
            if pos >= MAX_TOKENS {
                if self.handle_five_token_special_cases(&mut pos, &mut left) {
                    continue;
                }
            }
            
            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }
            
            // Get up to two tokens
            while more && pos <= MAX_TOKENS && (pos - left) < 2 {
                self.current = &mut self.tokenvec[pos] as *mut Token;
                more = self.tokenize();
                if more {
                    let current_token = unsafe { &*self.current };
                    if current_token.token_type == 'c' {
                        last_comment.copy_from(current_token);
                    } else {
                        last_comment.clear();
                        pos += 1;
                    }
                }
            }
            
            // Did we get 2 tokens? If not then we are done
            if pos - left < 2 {
                left = pos;
                continue;
            }
            
            // Apply two-token folding rules
            if self.fold_two_tokens(left, &mut pos, &mut left) {
                continue;
            }
            
            // Get third token for three-token folding
            while more && pos <= MAX_TOKENS && pos - left < 3 {
                self.current = &mut self.tokenvec[pos] as *mut Token;
                more = self.tokenize();
                if more {
                    let current_token = unsafe { &*self.current };
                    if current_token.token_type == 'c' {
                        last_comment.copy_from(current_token);
                    } else {
                        last_comment.clear();
                        pos += 1;
                    }
                }
            }
            
            // Do we have three tokens? If not then we are done
            if pos - left < 3 {
                left = pos;
                continue;
            }
            
            // Apply three-token folding rules
            if self.fold_three_tokens(left, &mut pos, &mut left) {
                continue;
            }
            
            // No folding - advance left pointer
            left += 1;
        }
        
        // Add back comment token if we have room (matches C logic)
        if left < MAX_TOKENS && last_comment.token_type == 'c' {
            self.tokenvec[left].copy_from(&last_comment);
            left += 1;
        }
        
        // Limit to MAX_TOKENS
        if left > MAX_TOKENS {
            left = MAX_TOKENS;
        }
        
        left
    }
    
    fn is_unary_op(&self, token: &Token) -> bool {
        if token.token_type != 'o' {
            return false;
        }
        
        // Check common unary operators by first character
        if token.len == 0 {
            return false;
        }
        
        match token.val[0] {
            b'+' | b'-' | b'!' | b'~' => true,
            b'N' | b'n' => {
                // Check for "NOT"
                if token.len >= 3 {
                    let val = &token.val[..token.len];
                    val.eq_ignore_ascii_case(b"NOT")
                } else {
                    false
                }
            },
            _ => false,
        }
    }
    
    fn handle_five_token_special_cases(&mut self, pos: &mut usize, left: &mut usize) -> bool {
        const MAX_TOKENS: usize = 5;
        
        let matches_pattern = 
            (self.tokenvec[0].token_type == '1' &&
             (self.tokenvec[1].token_type == 'o' ||
              self.tokenvec[1].token_type == ',') &&
             self.tokenvec[2].token_type == '(' &&
             self.tokenvec[3].token_type == '1' &&
             self.tokenvec[4].token_type == ')') ||
            (self.tokenvec[0].token_type == 'n' &&
             self.tokenvec[1].token_type == 'o' &&
             self.tokenvec[2].token_type == '(' &&
             (self.tokenvec[3].token_type == 'n' ||
              self.tokenvec[3].token_type == '1') &&
             self.tokenvec[4].token_type == ')') ||
            (self.tokenvec[0].token_type == '1' &&
             self.tokenvec[1].token_type == ')' &&
             self.tokenvec[2].token_type == ',' &&
             self.tokenvec[3].token_type == '(' &&
             self.tokenvec[4].token_type == '1') ||
            (self.tokenvec[0].token_type == 'n' &&
             self.tokenvec[1].token_type == ')' &&
             self.tokenvec[2].token_type == 'o' &&
             self.tokenvec[3].token_type == '(' &&
             self.tokenvec[4].token_type == 'n');
             
        if matches_pattern {
            if *pos > MAX_TOKENS {
                let temp = self.tokenvec[MAX_TOKENS];
                self.tokenvec[1] = temp;
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
    
    fn fold_two_tokens(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        // String folding: "foo" "bar" -> "foo"
        if self.tokenvec[left].token_type == 's' &&
           self.tokenvec[left + 1].token_type == 's' {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // Semicolon folding: ;; -> ;
        if self.tokenvec[left].token_type == ';' &&
           self.tokenvec[left + 1].token_type == ';' {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // Operator + unary -> remove unary
        if (self.tokenvec[left].token_type == 'o' ||
            self.tokenvec[left].token_type == '&') &&
           (self.is_unary_op(&self.tokenvec[left + 1]) ||
            self.tokenvec[left + 1].token_type == 't') {
            *pos -= 1;
            self.stats_folds += 1;
            *left_ptr = 0;
            return true;
        }
        
        // Left paren + unary -> remove unary
        if self.tokenvec[left].token_type == '(' &&
           self.is_unary_op(&self.tokenvec[left + 1]) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            return true;
        }
        
        // Syntax merge words (handles compound SQL phrases like "UNION ALL")
        if self.syntax_merge_words(left) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            return true;
        }
        
        // Semicolon + IF -> convert IF to TSQL type
        if self.tokenvec[left].token_type == ';' &&
           self.tokenvec[left + 1].token_type == 'f' &&
           self.tokenvec[left + 1].len >= 2 {
            let val = &self.tokenvec[left + 1].val[..2];
            if val.eq_ignore_ascii_case(b"IF") {
                self.tokenvec[left + 1].token_type = 'T';
                return true;
            }
        }
        
        // Bareword/Variable + LeftParen -> check if it's a function
        if (self.tokenvec[left].token_type == 'n' || self.tokenvec[left].token_type == 'v') &&
           self.tokenvec[left + 1].token_type == '(' {
            if self.is_function_name(&self.tokenvec[left]) {
                self.tokenvec[left].token_type = 'f';
                return true;
            }
        }
        
        // IN/NOT IN keyword context handling
        if self.tokenvec[left].token_type == 'k' &&
           self.is_in_keyword(&self.tokenvec[left]) {
            if self.tokenvec[left + 1].token_type == '(' {
                self.tokenvec[left].token_type = 'o';
            } else {
                self.tokenvec[left].token_type = 'n';
            }
            return true;
        }
        
        // LIKE operator context handling
        if self.tokenvec[left].token_type == 'o' &&
           self.is_like_operator(&self.tokenvec[left]) &&
           self.tokenvec[left + 1].token_type == '(' {
            self.tokenvec[left].token_type = 'f';
            return true;
        }
        
        // SQL type followed by various tokens
        if self.tokenvec[left].token_type == 't' &&
           (self.tokenvec[left + 1].token_type == 'n' ||
            self.tokenvec[left + 1].token_type == '1' ||
            self.tokenvec[left + 1].token_type == 't' ||
            self.tokenvec[left + 1].token_type == '(' ||
            self.tokenvec[left + 1].token_type == 'f' ||
            self.tokenvec[left + 1].token_type == 'v' ||
            self.tokenvec[left + 1].token_type == 's') {
            self.tokenvec[left] = self.tokenvec[left + 1];
            *pos -= 1;
            self.stats_folds += 1;
            *left_ptr = 0;
            return true;
        }
        
        // COLLATE + bareword
        if self.tokenvec[left].token_type == 'A' &&
           self.tokenvec[left + 1].token_type == 'n' {
            // Check if bareword has underscore (indicates collation type)
            if self.tokenvec[left + 1].val[..self.tokenvec[left + 1].len].contains(&b'_') {
                self.tokenvec[left + 1].token_type = 't';
                *left_ptr = 0;
            }
            return true;
        }
        
        // Backslash handling
        if self.tokenvec[left].token_type == '\\' {
            if self.is_arithmetic_op(&self.tokenvec[left + 1]) {
                self.tokenvec[left].token_type = '1';
            } else {
                self.tokenvec[left] = self.tokenvec[left + 1];
                *pos -= 1;
                self.stats_folds += 1;
            }
            *left_ptr = 0;
            return true;
        }
        
        // Left paren + left paren -> fold
        if self.tokenvec[left].token_type == '(' &&
           self.tokenvec[left + 1].token_type == '(' {
            *pos -= 1;
            *left_ptr = 0;
            self.stats_folds += 1;
            return true;
        }
        
        // Right paren + right paren -> fold
        if self.tokenvec[left].token_type == ')' &&
           self.tokenvec[left + 1].token_type == ')' {
            *pos -= 1;
            *left_ptr = 0;
            self.stats_folds += 1;
            return true;
        }
        
        // Left brace + bareword
        if self.tokenvec[left].token_type == '{' &&
           self.tokenvec[left + 1].token_type == 'n' {
            if self.tokenvec[left + 1].len == 0 {
                self.tokenvec[left + 1].token_type = 'X';
                return false; // Return early with evil token
            }
            // ODBC/MySQL {foo expr} -> expr
            *left_ptr = 0;
            *pos -= 2;
            self.stats_folds += 2;
            return true;
        }
        
        // Anything + right brace -> fold
        if self.tokenvec[left + 1].token_type == '}' {
            *pos -= 1;
            *left_ptr = 0;
            self.stats_folds += 1;
            return true;
        }
        
        false
    }
    
    /// Syntax merge words - handles compound SQL phrases like "UNION ALL"
    fn syntax_merge_words(&mut self, left: usize) -> bool {
        if left + 1 >= self.tokenvec.len() {
            return false;
        }
        
        let token1 = &self.tokenvec[left];
        let token2 = &self.tokenvec[left + 1];
        
        // Only merge specific token types
        if !matches!(token1.token_type, 'k' | 'n' | 'o' | 'f') || 
           !matches!(token2.token_type, 'k' | 'n' | 'o' | 'f') {
            return false;
        }
        
        // Create merged string
        let mut merged = [0u8; 32];
        let len1 = token1.len.min(15);
        let len2 = token2.len.min(15);
        
        if len1 + len2 + 1 > 31 {
            return false; // Too long to merge
        }
        
        merged[..len1].copy_from_slice(&token1.val[..len1]);
        merged[len1] = b' ';
        merged[len1 + 1..len1 + 1 + len2].copy_from_slice(&token2.val[..len2]);
        
        // Check if merged phrase is a known SQL construct
        if let Ok(phrase) = std::str::from_utf8(&merged[..len1 + 1 + len2]) {
            let upper_phrase = phrase.to_uppercase();
            match upper_phrase.as_str() {
                "UNION ALL" | "UNION DISTINCT" | "ORDER BY" | "GROUP BY" |
                "NOT IN" | "NOT LIKE" | "NOT EXISTS" | "IS NULL" | "IS NOT" |
                "LEFT JOIN" | "RIGHT JOIN" | "INNER JOIN" | "FULL JOIN" |
                "INTO OUTFILE" | "INTO DUMPFILE" => {
                    // Update the first token with merged value
                    self.tokenvec[left].len = len1 + 1 + len2;
                    self.tokenvec[left].val = merged;
                    return true;
                }
                _ => false
            }
        } else {
            false
        }
    }
    
    fn is_function_name(&self, token: &Token) -> bool {
        if let Ok(name) = std::str::from_utf8(&token.val[..token.len]) {
            let upper_name = name.to_uppercase();
            matches!(upper_name.as_str(),
                "USER_ID" | "USER_NAME" | "DATABASE" | "PASSWORD" | "USER" |
                "CURRENT_USER" | "CURRENT_DATE" | "CURRENT_TIME" | "CURRENT_TIMESTAMP" |
                "LOCALTIME" | "LOCALTIMESTAMP")
        } else {
            false
        }
    }
    
    fn is_in_keyword(&self, token: &Token) -> bool {
        if let Ok(name) = std::str::from_utf8(&token.val[..token.len]) {
            let upper_name = name.to_uppercase();
            matches!(upper_name.as_str(), "IN" | "NOT IN")
        } else {
            false
        }
    }
    
    fn is_like_operator(&self, token: &Token) -> bool {
        if let Ok(name) = std::str::from_utf8(&token.val[..token.len]) {
            let upper_name = name.to_uppercase();
            matches!(upper_name.as_str(), "LIKE" | "NOT LIKE")
        } else {
            false
        }
    }
    
    fn is_arithmetic_op(&self, token: &Token) -> bool {
        if token.token_type != 'o' {
            return false;
        }
        matches!(token.val[0], b'+' | b'-' | b'*' | b'/' | b'%')
    }
    
    fn fold_three_tokens(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        // Number operator number -> number
        if self.tokenvec[left].token_type == '1' &&
           self.tokenvec[left + 1].token_type == 'o' &&
           self.tokenvec[left + 2].token_type == '1' {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // Operator X operator -> operator (but not if X is left paren)
        if self.tokenvec[left].token_type == 'o' &&
           self.tokenvec[left + 1].token_type != '(' &&
           self.tokenvec[left + 2].token_type == 'o' {
            *left_ptr = 0;
            *pos -= 2;
            return true;
        }
        
        // Logic operator X logic operator -> logic operator
        if self.tokenvec[left].token_type == '&' &&
           self.tokenvec[left + 2].token_type == '&' {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // Variable operator (variable|number|bareword) -> variable
        if self.tokenvec[left].token_type == 'v' &&
           self.tokenvec[left + 1].token_type == 'o' &&
           (self.tokenvec[left + 2].token_type == 'v' ||
            self.tokenvec[left + 2].token_type == '1' ||
            self.tokenvec[left + 2].token_type == 'n') {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // (Bareword|number) operator (number|bareword) -> bareword
        if (self.tokenvec[left].token_type == 'n' ||
            self.tokenvec[left].token_type == '1') &&
           self.tokenvec[left + 1].token_type == 'o' &&
           (self.tokenvec[left + 2].token_type == '1' ||
            self.tokenvec[left + 2].token_type == 'n') {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // PostgreSQL casting: X::TYPE -> X
        if (self.tokenvec[left].token_type == 'n' ||
            self.tokenvec[left].token_type == '1' ||
            self.tokenvec[left].token_type == 'v' ||
            self.tokenvec[left].token_type == 's') &&
           self.tokenvec[left + 1].token_type == 'o' &&
           self.tokenvec[left + 2].token_type == 't' {
            // Check if operator is "::"
            if self.tokenvec[left + 1].len == 2 &&
               self.tokenvec[left + 1].val[0] == b':' &&
               self.tokenvec[left + 1].val[1] == b':' {
                *pos -= 2;
                *left_ptr = 0;
                self.stats_folds += 2;
                return true;
            }
        }
        
        // X,Y -> X (comma folding)
        if (self.tokenvec[left].token_type == 'n' ||
            self.tokenvec[left].token_type == '1' ||
            self.tokenvec[left].token_type == 's' ||
            self.tokenvec[left].token_type == 'v') &&
           self.tokenvec[left + 1].token_type == ',' &&
           (self.tokenvec[left + 2].token_type == '1' ||
            self.tokenvec[left + 2].token_type == 'n' ||
            self.tokenvec[left + 2].token_type == 's' ||
            self.tokenvec[left + 2].token_type == 'v') {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // Expression/Group/Comma + unary + left paren -> remove unary
        if (self.tokenvec[left].token_type == 'E' ||
            self.tokenvec[left].token_type == 'B' ||
            self.tokenvec[left].token_type == ',') &&
           self.is_unary_op(&self.tokenvec[left + 1]) &&
           self.tokenvec[left + 2].token_type == '(' {
            self.tokenvec[left + 1] = self.tokenvec[left + 2];
            *pos -= 1;
            *left_ptr = 0;
            return true;
        }
        
        // Keyword/Expression/Group + unary + other -> remove unary  
        if (self.tokenvec[left].token_type == 'k' ||
            self.tokenvec[left].token_type == 'E' ||
            self.tokenvec[left].token_type == 'B') &&
           self.is_unary_op(&self.tokenvec[left + 1]) &&
           (self.tokenvec[left + 2].token_type == '1' ||
            self.tokenvec[left + 2].token_type == 'n' ||
            self.tokenvec[left + 2].token_type == 'v' ||
            self.tokenvec[left + 2].token_type == 's' ||
            self.tokenvec[left + 2].token_type == 'f') {
            self.tokenvec[left + 1] = self.tokenvec[left + 2];
            *pos -= 1;
            *left_ptr = 0;
            return true;
        }
        
        // Comma + unary + other -> remove unary and backtrack
        if self.tokenvec[left].token_type == ',' &&
           self.is_unary_op(&self.tokenvec[left + 1]) &&
           (self.tokenvec[left + 2].token_type == '1' ||
            self.tokenvec[left + 2].token_type == 'n' ||
            self.tokenvec[left + 2].token_type == 'v' ||
            self.tokenvec[left + 2].token_type == 's') {
            self.tokenvec[left + 1] = self.tokenvec[left + 2];
            *left_ptr = 0;
            *pos -= 3; // Back up to reparse
            return true;
        }
        
        // Comma + unary + function -> just remove unary
        if self.tokenvec[left].token_type == ',' &&
           self.is_unary_op(&self.tokenvec[left + 1]) &&
           self.tokenvec[left + 2].token_type == 'f' {
            self.tokenvec[left + 1] = self.tokenvec[left + 2];
            *pos -= 1;
            *left_ptr = 0;
            return true;
        }
        
        // bareword.bareword -> bareword (database.table notation)
        if self.tokenvec[left].token_type == 'n' &&
           self.tokenvec[left + 1].token_type == '.' &&
           self.tokenvec[left + 2].token_type == 'n' {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // Expression.bareword -> bareword  
        if self.tokenvec[left].token_type == 'E' &&
           self.tokenvec[left + 1].token_type == '.' &&
           self.tokenvec[left + 2].token_type == 'n' {
            self.tokenvec[left + 1] = self.tokenvec[left + 2];
            *pos -= 1;
            *left_ptr = 0;
            return true;
        }
        
        // Function + LeftParen + (not RightParen) -> check for 0-arg functions
        if self.tokenvec[left].token_type == 'f' &&
           self.tokenvec[left + 1].token_type == '(' &&
           self.tokenvec[left + 2].token_type != ')' {
            // USER() should be 0-arg, so if there are args it's not a function
            if let Ok(func_name) = std::str::from_utf8(&self.tokenvec[left].val[..self.tokenvec[left].len]) {
                if func_name.to_uppercase() == "USER" {
                    self.tokenvec[left].token_type = 'n';
                }
            }
        }
        
        false
    }

    /// Matches C's libinjection_sqli_check_fingerprint exactly
    pub fn check_fingerprint(&mut self) -> bool {
        self.blacklist() && self.not_whitelist()
    }
    
    /// Matches C's libinjection_sqli_blacklist exactly  
    fn blacklist(&mut self) -> bool {
        let fp_len = self.fingerprint.iter().position(|&b| b == 0).unwrap_or(8);
        
        if fp_len < 1 {
            self.reason = line!();
            return false;
        }
        
        // Convert to v1 format (matches C exactly)
        let mut fp2 = [0u8; 8];
        fp2[0] = b'0';
        for i in 0..fp_len {
            let mut ch = self.fingerprint[i];
            if ch >= b'a' && ch <= b'z' {
                ch -= 0x20; // Convert to uppercase
            }
            fp2[i + 1] = ch;
        }
        fp2[fp_len + 1] = 0;
        
        // Check against compiled fingerprints
        let v1_fingerprint = std::str::from_utf8(&fp2[..fp_len + 1]).unwrap_or("");
        let pat_match = fingerprint_data::is_fingerprint_match(v1_fingerprint);
        
        if !pat_match {
            self.reason = line!();
            return false;
        }
        
        true
    }

    pub fn get_fingerprint(&self) -> Fingerprint {
        Fingerprint::new(self.fingerprint)
    }
    
    /// Helper to get current fingerprint as string
    pub fn fingerprint_str(&self) -> &str {
        let len = self.fingerprint.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.fingerprint[..len]).unwrap_or("")
    }
    
    /// Matches C's libinjection_sqli_not_whitelist exactly
    /// Returns true if NOT whitelisted (i.e., is SQLi), false if whitelisted (not SQLi)
    pub fn not_whitelist(&mut self) -> bool {
        let tlen = self.fingerprint.iter().position(|&b| b == 0).unwrap_or(8);
        
        // Check for sp_password in input (special case)
        if tlen > 1 && self.fingerprint[tlen - 1] == b'c' {
            // Look for sp_password in input
            let haystack = self.s;
            let needle = b"sp_password";
            if self.my_memmem(haystack, needle).is_some() {
                self.reason = line!();
                return true;
            }
        }
        
        match tlen {
            2 => self.not_whitelist_case_2(),
            3 => self.not_whitelist_case_3(),
            4 | 5 => true, // No special whitelist rules for 4-5 tokens
            _ => true,
        }
    }
    
    fn my_memmem(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        
        for i in 0..=haystack.len().saturating_sub(needle.len()) {
            if haystack[i..].starts_with(needle) {
                return Some(i);
            }
        }
        
        None
    }
    
    fn not_whitelist_case_2(&mut self) -> bool {
        // Check if second token is UNION
        if self.fingerprint[1] == b'U' { // TYPE_UNION
            if self.stats_tokens == 2 {
                self.reason = line!();
                return false; // "1 UNION" with no folding - likely not SQLi
            } else {
                self.reason = line!();
                return true; // Has folding or other tokens - likely SQLi
            }
        }
        
        // If comment token starts with '#', ignore (too many false positives)
        if self.tokenvec[1].val[0] == b'#' {
            self.reason = line!();
            return false;
        }
        
        // For 'nc' pattern (bareword + comment), only '/*' comments are SQLi
        if self.tokenvec[0].token_type == 'n' &&
           self.tokenvec[1].token_type == 'c' &&
           self.tokenvec[1].val[0] != b'/' {
            self.reason = line!();
            return false;
        }
        
        // For '1c' pattern ending with '/*', it's SQLi
        if self.tokenvec[0].token_type == '1' &&
           self.tokenvec[1].token_type == 'c' &&
           self.tokenvec[1].val[0] == b'/' {
            return true;
        }
        
        // Special handling for number + comment patterns (matches C exactly)
        if self.tokenvec[0].token_type == '1' &&
           self.tokenvec[1].token_type == 'c' {
            
            if self.stats_tokens > 2 {
                self.reason = line!();
                return true; // Folding occurred - likely SQLi
            }
            
            // Check original string after number token (matches C logic)
            let ch = self.s[self.tokenvec[0].len];
            if ch <= 32 {
                // Next char was whitespace, e.g. "1234 --"
                return true;
            }
            if ch == b'/' && self.s[self.tokenvec[0].len + 1] == b'*' {
                return true;
            }
            if ch == b'-' && self.s[self.tokenvec[0].len + 1] == b'-' {
                return true;
            }
            
            self.reason = line!();
            return false;
        }
        
        // Check for long '--' comments (false positive reduction)
        if self.tokenvec[1].len > 2 && self.tokenvec[1].val[0] == b'-' {
            self.reason = line!();
            return false;
        }
        
        true
    }
    
    fn not_whitelist_case_3(&mut self) -> bool {
        let fp_str = std::str::from_utf8(&self.fingerprint[..3]).unwrap_or("");
        
        // Handle 3-token patterns like 'sos', 's&s', etc. (matches C exactly)
        if fp_str == "sos" || fp_str == "s&s" {
            let has_no_open_quote = self.tokenvec[0].str_open == CHAR_NULL;
            let has_no_close_quote = self.tokenvec[2].str_close == CHAR_NULL;
            let quotes_match = self.tokenvec[0].str_close == self.tokenvec[2].str_open;
            
            if has_no_open_quote && has_no_close_quote && quotes_match {
                self.reason = line!();
                return true; // Pattern like ...foo" + "bar...
            }
            
            if self.stats_tokens == 3 {
                self.reason = line!();
                return false; // Simple string concatenation
            }
            
            self.reason = line!();
            return false;
        } else if fp_str == "s&n" || fp_str == "n&1" || 
                  fp_str == "1&1" || fp_str == "1&v" || fp_str == "1&s" {
            if self.stats_tokens == 3 {
                self.reason = line!();
                return false; // Simple expressions like "sexy and 17"
            }
        } else if self.tokenvec[1].token_type == 'k' {
            // Check for keyword patterns (matches C exactly)
            if self.tokenvec[1].len < 5 || self.cstrcasecmp(b"INTO", &self.tokenvec[1].val[..4]) != 0 {
                self.reason = line!();
                return false; // Not dangerous unless it's "INTO OUTFILE" or "INTO DUMPFILE"
            }
        }
        
        true
    }
    
    /// Case-insensitive string comparison (matches C)
    fn cstrcasecmp(&self, a: &[u8], b: &[u8]) -> i32 {
        let n = a.len().min(b.len());
        
        for i in 0..n {
            let mut cb = b[i];
            if cb >= b'a' && cb <= b'z' {
                cb -= 0x20;
            }
            
            if a[i] != cb {
                return a[i] as i32 - cb as i32;
            } else if a[i] == 0 {
                return -1;
            }
        }
        
        match a.len().cmp(&b.len()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

pub fn detect_sqli(input: &[u8]) -> SqliResult {
    SqliDetector::new().detect(input)
}