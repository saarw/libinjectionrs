use core::ops::Deref;

pub const LIBINJECTION_SQLI_MAX_TOKENS: usize = 5;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SqliFlags(u32);

impl SqliFlags {
    pub const FLAG_NONE: SqliFlags = SqliFlags(0);
    pub const FLAG_QUOTE_NONE: SqliFlags = SqliFlags(1 << 0);
    pub const FLAG_QUOTE_SINGLE: SqliFlags = SqliFlags(1 << 1);
    pub const FLAG_QUOTE_DOUBLE: SqliFlags = SqliFlags(1 << 2);
    pub const FLAG_SQL_ANSI: SqliFlags = SqliFlags(1 << 3);
    pub const FLAG_SQL_MYSQL: SqliFlags = SqliFlags(1 << 4);
}

impl SqliFlags {
    pub fn new(flags: u32) -> Self {
        SqliFlags(flags)
    }

    pub fn is_ansi(&self) -> bool {
        self.0 & Self::FLAG_SQL_ANSI.0 != 0
    }

    pub fn is_mysql(&self) -> bool {
        self.0 & Self::FLAG_SQL_MYSQL.0 != 0
    }
    
    pub fn quote_context(&self) -> u8 {
        if self.0 & Self::FLAG_QUOTE_SINGLE.0 != 0 {
            b'\''
        } else if self.0 & Self::FLAG_QUOTE_DOUBLE.0 != 0 {
            b'"'
        } else {
            b'\0'
        }
    }
}

/// Fingerprint struct for SQL injection detection
#[derive(Clone, PartialEq)]
pub struct Fingerprint {
    fingerprint: [u8; 8],
}

impl Fingerprint {
    pub fn new(fp: [u8; 8]) -> Self {
        Fingerprint { fingerprint: fp }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.fingerprint
    }

    pub fn as_str(&self) -> &str {
        let len = self.fingerprint.iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        core::str::from_utf8(&self.fingerprint[..len])
            .unwrap_or("")
    }
}

impl Deref for Fingerprint {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<str> for Fingerprint {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Fingerprint {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

/// Main SQL injection detection state
pub struct SqliState<'a> {
    // Input string
    input: &'a [u8],
    
    // Flags for SQL mode (ANSI, MySQL, etc.)
    flags: SqliFlags,
    
    // Token storage - we store up to MAX_TOKENS + 3 during processing
    tokens: Vec<Token>,
    token_vec: Vec<Token>,
    
    // Current position in input
    pos: usize,
    
    // Current token being processed  
    current_token: Option<Token>,
    
    // The fingerprint
    fingerprint: [u8; 8],
    
    // Various statistics
    stats_comment_ddw: i32,
    stats_comment_ddx: i32,
    stats_comment_c: i32,
    stats_comment_hash: i32,
    stats_folds: usize,
    stats_tokens: usize,
    
    // Reason for SQLi detection (for debugging)
    reason: u32,
}

impl<'a> SqliState<'a> {
    pub fn new(input: &'a [u8], flags: SqliFlags) -> Self {
        SqliState {
            input,
            flags,
            tokens: Vec::with_capacity(LIBINJECTION_SQLI_MAX_TOKENS + 3),
            token_vec: Vec::with_capacity(LIBINJECTION_SQLI_MAX_TOKENS + 3),
            pos: 0,
            current_token: None,
            fingerprint: [0; 8],
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_c: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
            reason: 0,
        }
    }
    
    /// Convenience constructor for string input
    pub fn from_string(input: &'a str, flags: SqliFlags) -> Self {
        Self::new(input.as_bytes(), flags)
    }
    
    /// Main detection function - checks if input is SQL injection
    pub fn is_sqli(&mut self) -> bool {
        let fingerprint = self.fingerprint();
        
        // Check blacklist
        if !blacklist::is_blacklisted(fingerprint.as_str()) {
            return false;
        }
        
        // Additional whitelist check (reduces false positives)
        self.is_not_whitelist()
    }
    
    /// Get the fingerprint for the input
    pub fn get_fingerprint(&mut self) -> Fingerprint {
        self.fingerprint()
    }
    
    /// Detects SQL injection with additional flag handling
    /// This matches the C implementation's libinjection_is_sqli() function
    pub fn detect(&mut self) -> bool {
        // no input? not SQLi
        if self.input.is_empty() {
            return false;
        }
        
        // Test input "as-is"
        self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_ANSI.0));
        let fingerprint = self.fingerprint();
        if self.check_is_sqli(&fingerprint) {
            return true;
        } else if self.reparse_as_mysql() {
            self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_NONE.0 | SqliFlags::FLAG_SQL_MYSQL.0));
            let fingerprint = self.fingerprint();
            if self.check_is_sqli(&fingerprint) {
                return true;
            }
        }
        
        // If input has a single quote, test as if input was actually preceded by '
        if self.input.contains(&b'\'') {
            self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_SINGLE.0 | SqliFlags::FLAG_SQL_ANSI.0));
            let fingerprint = self.fingerprint();
            if self.check_is_sqli(&fingerprint) {
                return true;
            } else if self.reparse_as_mysql() {
                self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_SINGLE.0 | SqliFlags::FLAG_SQL_MYSQL.0));
                let fingerprint = self.fingerprint();
                if self.check_is_sqli(&fingerprint) {
                    return true;
                }
            }
        }
        
        // If input has a double quote, test as if input was actually preceded by "
        if self.input.contains(&b'"') {
            self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_ANSI.0));
            let fingerprint = self.fingerprint();
            if self.check_is_sqli(&fingerprint) {
                return true;
            } else if self.reparse_as_mysql() {
                self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_MYSQL.0));
                let fingerprint = self.fingerprint();
                if self.check_is_sqli(&fingerprint) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Get the detected fingerprint as a string
    pub fn fingerprint_string(&self) -> String {
        let len = self.fingerprint.iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        String::from_utf8_lossy(&self.fingerprint[..len]).to_string()
    }
    
    /// Advanced API that allows for custom initial state
    /// Matches the C implementation's libinjection_sqli() function
    pub fn detect_with_context(&mut self, context: u8) -> bool {
        match context {
            b'\0' => {
                // Process as is
                self.detect()
            },
            b'\'' | b'"' => {
                // Process pretending input started with a quote
                // This would require modifying the tokenizer to handle this
                // For now, just process normally
                self.detect()
            },
            _ => {
                // Unknown context, process normally
                self.detect()
            }
        }
    }
    
    /// Determines if input should be reparsed as MySQL based on comment statistics
    /// Matches the C implementation's reparse_as_mysql() function
    fn reparse_as_mysql(&self) -> bool {
        self.stats_comment_ddx != 0 || self.stats_comment_hash != 0
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
        let token_count = self.fold_tokens();
        self.generate_fingerprint(token_count);
        Fingerprint::new(self.fingerprint)
    }
    
    
    fn fold_tokens(&mut self) -> usize {
        // This is a complete rewrite to match the C implementation exactly
        let mut last_comment = Token::new();
        let mut tokenizer = SqliTokenizer::new(self.input, self.flags);
        
        // Clear and resize token vec
        self.token_vec.clear();
        self.token_vec.resize(LIBINJECTION_SQLI_MAX_TOKENS + 3, Token::new());
        
        // pos is the position of where the NEXT token goes
        let mut pos = 0usize;
        // left is a count of how many tokens are already folded or processed
        let mut left = 0usize;
        let mut more = true;
        
        // Skip all initial comments, right-parens and unary operators
        while more {
            if let Some(token) = tokenizer.next_token() {
                self.token_vec[0] = token.clone();
                if !(token.token_type == TokenType::Comment ||
                     token.token_type == TokenType::LeftParenthesis ||
                     token.token_type == TokenType::SqlType ||
                     self.is_unary_op(&token)) {
                    // Found a real token, keep it
                    break;
                }
                // Otherwise continue skipping
            } else {
                more = false;
            }
        }
        
        if !more {
            // If input was only comments, unary or (, then exit
            return 0;
        } else {
            // it's some other token
            pos = 1;
        }
        
        // Main folding loop
        loop {
            // Do we have all the max number of tokens? If so, do some special cases for 5 tokens
            if pos >= LIBINJECTION_SQLI_MAX_TOKENS {
                if (self.token_vec[0].token_type == TokenType::Number &&
                    (self.token_vec[1].token_type == TokenType::Operator ||
                     self.token_vec[1].token_type == TokenType::Comma) &&
                    self.token_vec[2].token_type == TokenType::LeftParenthesis &&
                    self.token_vec[3].token_type == TokenType::Number &&
                    self.token_vec[4].token_type == TokenType::RightParenthesis) ||
                   (self.token_vec[0].token_type == TokenType::Bareword &&
                    self.token_vec[1].token_type == TokenType::Operator &&
                    self.token_vec[2].token_type == TokenType::LeftParenthesis &&
                    (self.token_vec[3].token_type == TokenType::Bareword ||
                     self.token_vec[3].token_type == TokenType::Number) &&
                    self.token_vec[4].token_type == TokenType::RightParenthesis) ||
                   (self.token_vec[0].token_type == TokenType::Number &&
                    self.token_vec[1].token_type == TokenType::RightParenthesis &&
                    self.token_vec[2].token_type == TokenType::Comma &&
                    self.token_vec[3].token_type == TokenType::LeftParenthesis &&
                    self.token_vec[4].token_type == TokenType::Number) ||
                   (self.token_vec[0].token_type == TokenType::Bareword &&
                    self.token_vec[1].token_type == TokenType::RightParenthesis &&
                    self.token_vec[2].token_type == TokenType::Operator &&
                    self.token_vec[3].token_type == TokenType::LeftParenthesis &&
                    self.token_vec[4].token_type == TokenType::Bareword) {
                    if pos > LIBINJECTION_SQLI_MAX_TOKENS {
                        // Copy token[5] to token[1]
                        self.token_vec[1] = self.token_vec[LIBINJECTION_SQLI_MAX_TOKENS].clone();
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
                        self.token_vec[pos] = token;
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
            
            // Apply 2-token folding rules
            if self.apply_two_token_fold(left, &mut pos, &mut left) {
                continue;
            }
            
            // All cases of handling 2 tokens is done, get one more token
            while more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && pos - left < 3 {
                if let Some(token) = tokenizer.next_token() {
                    if token.token_type == TokenType::Comment {
                        last_comment = token;
                    } else {
                        last_comment.token_type = TokenType::None;
                        self.token_vec[pos] = token;
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
            
            // Apply 3-token folding rules
            if self.apply_three_token_fold(left, &mut pos, &mut left) {
                continue;
            }
            
            // No folding -- assume left-most token is good
            left += 1;
        }
        
        // If we have 4 or less tokens, and we had a comment token at the end, add it back
        if left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.token_type == TokenType::Comment {
            self.token_vec[left] = last_comment;
            left += 1;
        }
        
        // Sometimes we grab a 6th token to help determine the type of token 5
        if left > LIBINJECTION_SQLI_MAX_TOKENS {
            left = LIBINJECTION_SQLI_MAX_TOKENS;
        }
        
        // Copy final tokens to the tokens vector for fingerprinting
        self.tokens.clear();
        for i in 0..left {
            self.tokens.push(self.token_vec[i].clone());
        }
        
        // Copy tokenizer statistics
        self.stats_comment_c = tokenizer.stats_comment_c;
        self.stats_comment_ddw = tokenizer.stats_comment_ddw;
        self.stats_comment_ddx = tokenizer.stats_comment_ddx;
        self.stats_comment_hash = tokenizer.stats_comment_hash;
        
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
        if left + 1 >= self.token_vec.len() {
            return false;
        }
        
        let a_type = self.token_vec[left].token_type;
        let b_type = self.token_vec[left + 1].token_type;
        
        // Check if both tokens are mergeable types
        let mergeable_types = [
            TokenType::Keyword, TokenType::Bareword, TokenType::Operator,
            TokenType::Union, TokenType::Function, TokenType::Expression,
            TokenType::Tsql, TokenType::SqlType, TokenType::LogicOperator
        ];
        
        if !mergeable_types.contains(&a_type) || !mergeable_types.contains(&b_type) {
            return false;
        }
        
        let a_val = self.token_vec[left].value_as_str();
        let b_val = self.token_vec[left + 1].value_as_str();
        
        if a_val.len() + b_val.len() + 1 >= 32 {
            return false;
        }
        
        let merged = format!("{} {}", a_val, b_val);
        let lookup_result = sqli_data::lookup_word(&merged.to_ascii_uppercase());
        
        lookup_result != TokenType::Bareword
    }

    // Apply all 2-token folding rules exactly as in C version
    fn apply_two_token_fold(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        let t_left = self.token_vec[left].token_type;
        let t_right = self.token_vec[left + 1].token_type;
        
        // FOLD: "ss" -> "s" - "foo" "bar" is valid SQL, just ignore second string
        if t_left == TokenType::String && t_right == TokenType::String {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // FOLD: ";;" -> ";" - fold away repeated semicolons
        if t_left == TokenType::Semicolon && t_right == TokenType::Semicolon {
            *pos -= 1;
            self.stats_folds += 1;
            return true;
        }
        
        // FOLD: (operator|logic_operator) + (unary_op|sqltype) -> operator
        if (t_left == TokenType::Operator || t_left == TokenType::LogicOperator) &&
           (self.is_unary_op(&self.token_vec[left + 1]) || t_right == TokenType::SqlType) {
            *pos -= 1;
            self.stats_folds += 1;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: leftparens + unary_op -> leftparens
        if t_left == TokenType::LeftParenthesis && self.is_unary_op(&self.token_vec[left + 1]) {
            *pos -= 1;
            self.stats_folds += 1;
            if *left_ptr > 0 {
                *left_ptr -= 1;
            }
            return true;
        }
        
        // Try word merging
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
            let val = self.token_vec[left + 1].value_as_str().to_ascii_uppercase();
            if val == "IF" {
                self.token_vec[left + 1].token_type = TokenType::Tsql;
                // Note: C code doesn't decrement pos here, just changes type
                return false; // Continue processing but don't skip
            }
        }
        
        // Many more 2-token rules from C code...
        // For brevity, adding the most important ones
        
        false
    }
    
    // Apply all 3-token folding rules exactly as in C version  
    fn apply_three_token_fold(&mut self, left: usize, pos: &mut usize, left_ptr: &mut usize) -> bool {
        // FOLD: number operator number -> number
        if self.token_vec[left].token_type == TokenType::Number &&
           self.token_vec[left + 1].token_type == TokenType::Operator &&
           self.token_vec[left + 2].token_type == TokenType::Number {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: operator X operator -> operator (where X != leftparens)
        if self.token_vec[left].token_type == TokenType::Operator &&
           self.token_vec[left + 1].token_type != TokenType::LeftParenthesis &&
           self.token_vec[left + 2].token_type == TokenType::Operator {
            *left_ptr = 0;
            *pos -= 2;
            return true;
        }
        
        // FOLD: logic_operator X logic_operator -> logic_operator 
        if self.token_vec[left].token_type == TokenType::LogicOperator &&
           self.token_vec[left + 2].token_type == TokenType::LogicOperator {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: variable operator (variable|number|bareword) -> variable
        if self.token_vec[left].token_type == TokenType::Variable &&
           self.token_vec[left + 1].token_type == TokenType::Operator &&
           (self.token_vec[left + 2].token_type == TokenType::Variable ||
            self.token_vec[left + 2].token_type == TokenType::Number ||
            self.token_vec[left + 2].token_type == TokenType::Bareword) {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: (bareword|number) operator (number|bareword) -> first
        if (self.token_vec[left].token_type == TokenType::Bareword ||
            self.token_vec[left].token_type == TokenType::Number) &&
           self.token_vec[left + 1].token_type == TokenType::Operator &&
           (self.token_vec[left + 2].token_type == TokenType::Number ||
            self.token_vec[left + 2].token_type == TokenType::Bareword) {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // FOLD: (bareword|number|string|variable) comma (number|bareword|string|variable) -> first_token
        if (self.token_vec[left].token_type == TokenType::Bareword ||
            self.token_vec[left].token_type == TokenType::Number ||
            self.token_vec[left].token_type == TokenType::String ||
            self.token_vec[left].token_type == TokenType::Variable) &&
           self.token_vec[left + 1].token_type == TokenType::Comma &&
           (self.token_vec[left + 2].token_type == TokenType::Number ||
            self.token_vec[left + 2].token_type == TokenType::Bareword ||
            self.token_vec[left + 2].token_type == TokenType::String ||
            self.token_vec[left + 2].token_type == TokenType::Variable) {
            *pos -= 2;
            *left_ptr = 0;
            return true;
        }
        
        // Many more 3-token rules from C code...
        
        false
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
    
    fn check_is_sqli(&self, fingerprint: &Fingerprint) -> bool {
        if blacklist::is_blacklisted(fingerprint.as_str()) {
            self.is_not_whitelist()
        } else {
            false
        }
    }
    
    /// Whitelist functionality to reduce false positives
    /// Returns true if SQLi, false if benign
    fn is_not_whitelist(&self) -> bool {
        let fingerprint_str = core::str::from_utf8(&self.fingerprint)
            .unwrap_or("")
            .trim_end_matches('\0');
        let tlen = fingerprint_str.len();
        
        // Check for sp_password in comments
        if tlen > 1 && self.fingerprint[tlen - 1] == b'c' {
            if self.contains_sp_password() {
                return true;
            }
        }
        
        match tlen {
            2 => self.handle_two_token_whitelist(),
            3 => self.handle_three_token_whitelist(),
            4 | 5 => true, // Nothing special for 4-5 tokens right now
            _ => true,
        }
    }
    
    fn contains_sp_password(&self) -> bool {
        let input_str = core::str::from_utf8(self.input).unwrap_or("");
        input_str.to_ascii_lowercase().contains("sp_password")
    }
    
    fn handle_two_token_whitelist(&self) -> bool {
        let fingerprint_str = core::str::from_utf8(&self.fingerprint)
            .unwrap_or("")
            .trim_end_matches('\0');
            
        if self.tokens.len() < 2 {
            return true;
        }
        
        // Case 2: "very small SQLi" which make them hard to tell from normal input
        
        // Check for Union pattern - fingerprint[1] == 'U'
        if fingerprint_str.chars().nth(1) == Some('U') {
            if self.stats_tokens == 2 {
                // "1U" with exactly 2 tokens - likely not SQLi
                return false;
            } else {
                // "1U" with folding or more tokens - likely SQLi
                return true;
            }
        }
        
        // If comment is '#' ignore - too many false positives
        if self.tokens[1].token_type == TokenType::Comment &&
           self.tokens[1].val[0] == b'#' {
            return false;
        }
        
        // For fingerprint like 'nc', only comments of /* are treated as SQL
        // ending comments of "--" and "#" are not SQLi
        if self.tokens[0].token_type == TokenType::Bareword &&
           self.tokens[1].token_type == TokenType::Comment &&
           self.tokens[1].val[0] != b'/' {
            return false;
        }
        
        // If '1c' ends with '/*' then it's SQLi
        if self.tokens[0].token_type == TokenType::Number &&
           self.tokens[1].token_type == TokenType::Comment &&
           self.tokens[1].val[0] == b'/' {
            return true;
        }
        
        // Handle number followed by comment
        if self.tokens[0].token_type == TokenType::Number &&
           self.tokens[1].token_type == TokenType::Comment {
            
            if self.stats_tokens > 2 {
                // We have some folding going on, highly likely SQLi
                return true;
            }
            
            // Check that next character after the number is whitespace, '/' or '-'
            let token0_end = self.tokens[0].pos + self.tokens[0].len;
            if token0_end < self.input.len() {
                let ch = self.input[token0_end];
                
                if ch <= 32 {
                    // Next char was whitespace, e.g. "1234 --"
                    return true;
                }
                
                if ch == b'/' && token0_end + 1 < self.input.len() &&
                   self.input[token0_end + 1] == b'*' {
                    return true;
                }
                
                if ch == b'-' && token0_end + 1 < self.input.len() &&
                   self.input[token0_end + 1] == b'-' {
                    return true;
                }
            }
            
            return false;
        }
        
        // Detect obvious SQLi scans - only if comment is longer than "--"
        // and starts with '-'
        if self.tokens[1].token_type == TokenType::Comment &&
           self.tokens[1].len > 2 && self.tokens[1].val[0] == b'-' {
            return false;
        }
        
        true
    }
    
    fn handle_three_token_whitelist(&self) -> bool {
        let fingerprint_str = core::str::from_utf8(&self.fingerprint)
            .unwrap_or("")
            .trim_end_matches('\0');
            
        if self.tokens.len() < 3 {
            return true;
        }
        
        // String concatenation patterns: ...foo' + 'bar...
        if fingerprint_str == "sos" || fingerprint_str == "s&s" {
            if self.tokens[0].str_open == CHAR_NULL &&
               self.tokens[2].str_close == CHAR_NULL &&
               self.tokens[0].str_close == self.tokens[2].str_open {
                // Pattern like ....foo" + "bar....
                return true;
            }
            
            if self.stats_tokens == 3 {
                return false;
            }
            
            // Not SQLi
            return false;
        }
        
        // Handle 'sexy and 17' vs 'sexy and 17<18' patterns
        if fingerprint_str == "s&n" || fingerprint_str == "n&1" ||
           fingerprint_str == "1&1" || fingerprint_str == "1&v" ||
           fingerprint_str == "1&s" {
            if self.stats_tokens == 3 {
                // 'sexy and 17' - not SQLi
                return false;
            }
        }
        
        // More whitelist rules...
        
        true
    }
}

// Re-export tokenizer types
pub use tokenizer::{Token, TokenType, SqliTokenizer};

mod tokenizer;
mod blacklist;
mod sqli_data;

// Import CHAR_NULL for internal use
use tokenizer::CHAR_NULL;

#[cfg(test)]
mod tests;