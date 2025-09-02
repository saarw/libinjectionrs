use core::ops::Deref;

#[cfg(feature = "smallvec")]
use smallvec::SmallVec;

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
    #[cfg(feature = "smallvec")]
    pub tokens: SmallVec<[Token; 8]>,
    #[cfg(not(feature = "smallvec"))]
    pub tokens: Vec<Token>,
    #[cfg(feature = "smallvec")]
    token_vec: SmallVec<[Token; 8]>,
    #[cfg(not(feature = "smallvec"))]
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
            #[cfg(feature = "smallvec")]
            tokens: SmallVec::new(),
            #[cfg(not(feature = "smallvec"))]
            tokens: Vec::with_capacity(LIBINJECTION_SQLI_MAX_TOKENS + 3),
            #[cfg(feature = "smallvec")]
            token_vec: SmallVec::new(),
            #[cfg(not(feature = "smallvec"))]
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
        // C only uses MySQL mode for double quotes (libinjection_sqli.c:2303-2304)
        if self.input.contains(&b'"') {
            self.reset(SqliFlags::new(SqliFlags::FLAG_QUOTE_DOUBLE.0 | SqliFlags::FLAG_SQL_MYSQL.0));
            let fingerprint = self.fingerprint();
            if self.check_is_sqli(&fingerprint) {
                return true;
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
        
        // Post-process tokens to detect MySQL conditional comments
        // This matches C implementation behavior in libinjection_sqli.c lines 1942-1954
        self.detect_mysql_comments_in_tokens(token_count);
        
        self.generate_fingerprint(token_count);
        Fingerprint::new(self.fingerprint)
    }
    
    
    pub fn fold_tokens(&mut self) -> usize {
        /*
         * This implementation exactly matches the C version's control flow structure because
         * the original separate Rust folding functions had subtle differences in behavior:
         * 
         * 1. The C version uses a single large function with else-if chains that ensure
         *    exactly one folding rule executes per main loop iteration
         * 2. Some C folding rules fall through without 'continue', allowing multiple 
         *    rules to be checked in sequence before restarting the main loop
         * 3. The aggressive left pointer resets (left = 0) in C cause immediate restart
         *    from the beginning of the token array, enabling cascading folding effects
         * 4. The stats_folds incrementing patterns differ between 2-token and 3-token rules
         * 
         * The separate function approach in Rust couldn't replicate these nuances exactly,
         * particularly the fall-through behavior and the precise timing of main loop restarts.
         * By inlining all the logic with the exact same control flow as C, we ensure
         * identical folding behavior that produces matching fingerprints.
         */
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
        
        // Phase 1: Skip all initial comments, right-parens and unary operators (matches C lines 1366-1386)
        // This matches C's initial phase exactly - put tokens in tokenvec[0] and skip unwanted ones
        while more {
            if let Some(token) = tokenizer.next_token() {
                // Count all tokens processed for stats_tokens
                self.stats_tokens += 1;
                
                self.token_vec[0] = token.clone();
                if !(token.token_type == TokenType::Comment ||
                     token.token_type == TokenType::LeftParenthesis ||
                     token.token_type == TokenType::SqlType ||
                     self.is_unary_op(&token)) {
                    // Found a real token, keep it at position 0
                    break;
                }
                // Otherwise continue skipping - comments are ignored in this phase
            } else {
                more = false;
            }
        }
        
        if !more {
            // If input was only comments, unary or (, then exit (matches C lines 1380-1382)
            // But first copy tokenizer statistics so they're available for reparse detection
            self.stats_comment_c = tokenizer.stats_comment_c;
            self.stats_comment_ddw = tokenizer.stats_comment_ddw;
            self.stats_comment_ddx = tokenizer.stats_comment_ddx;
            self.stats_comment_hash = tokenizer.stats_comment_hash;
            return 0;
        } else {
            // it's some other token - first real token is now at position 0
            pos = 1;
        }
        
        // Main folding loop - matches C libinjection_sqli_fold exactly
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
                        // Copy token[5] to token[1], reset to position 2
                        self.token_vec[1] = self.token_vec[LIBINJECTION_SQLI_MAX_TOKENS].clone();
                        pos = 2;
                        left = 0;
                    } else {
                        // Reset to position 1 to continue processing
                        pos = 1;
                        left = 0;
                    }
                }
            }
            
            // Check termination condition - exit if no more tokens or we have enough
            if !more || left >= LIBINJECTION_SQLI_MAX_TOKENS {
                left = pos;
                break;
            }
            
            // Get up to two tokens
            while more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 2 {
                if let Some(token) = tokenizer.next_token() {
                    // Count all tokens processed for stats_tokens
                    self.stats_tokens += 1;
                    
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
            
            /* ALL 2-TOKEN FOLDING RULES - exactly matching C implementation with else-if chain */
            
            // FOLD: "ss" -> "s" - from apply_two_token_fold 
            // "foo" "bar" is valid SQL, just ignore second string
            if self.token_vec[left].token_type == TokenType::String &&
               self.token_vec[left + 1].token_type == TokenType::String {
                pos -= 1;
                self.stats_folds += 1;
                continue;
            
            // FOLD: ";;" -> ";" - from apply_two_token_fold
            // fold away repeated semicolons  
            } else if self.token_vec[left].token_type == TokenType::Semicolon &&
                      self.token_vec[left + 1].token_type == TokenType::Semicolon {
                pos -= 1;
                self.stats_folds += 1;
                continue;
            
            // FOLD: (operator|logic_operator) + (unary_op|sqltype) -> operator - from apply_two_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Operator ||
                       self.token_vec[left].token_type == TokenType::LogicOperator) &&
                      (self.is_unary_op(&self.token_vec[left + 1]) ||
                       self.token_vec[left + 1].token_type == TokenType::SqlType) {
                pos -= 1;
                self.stats_folds += 1;
                left = 0;
                continue;
            
            // FOLD: leftparens + unary_op -> leftparens - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::LeftParenthesis &&
                      self.is_unary_op(&self.token_vec[left + 1]) {
                pos -= 1;
                self.stats_folds += 1;
                if left > 0 {
                    left -= 1;
                }
                continue;
            
            // FOLD: word merging - from syntax_merge_words inlined
            } else if {
                // syntax_merge_words logic inlined
                let a_type = self.token_vec[left].token_type;
                let b_type = self.token_vec[left + 1].token_type;
                
                // Check if token a is of right type
                (a_type == TokenType::Keyword || a_type == TokenType::Bareword ||
                 a_type == TokenType::Operator || a_type == TokenType::Union ||
                 a_type == TokenType::Function || a_type == TokenType::Expression ||
                 a_type == TokenType::Tsql || a_type == TokenType::SqlType) &&
                
                // Check if token b is of right type  
                (b_type == TokenType::Keyword || b_type == TokenType::Bareword ||
                 b_type == TokenType::Operator || b_type == TokenType::Union ||
                 b_type == TokenType::Function || b_type == TokenType::Expression ||
                 b_type == TokenType::Tsql || b_type == TokenType::SqlType ||
                 b_type == TokenType::LogicOperator) &&
                
                {
                    let sz1 = self.token_vec[left].len;
                    let sz2 = self.token_vec[left + 1].len;
                    let sz3 = sz1 + sz2 + 1; // +1 for space in the middle
                    
                    if sz3 < 32 { // make sure there is room for ending null
                        // Create merged string: a.val + ' ' + b.val
                        let a_val = self.token_vec[left].value_as_str();
                        let b_val = self.token_vec[left + 1].value_as_str();
                        let merged_original = format!("{} {}", a_val, b_val);
                        let merged_upper = merged_original.to_ascii_uppercase();
                        
                        let lookup_result = sqli_data::lookup_word(&merged_upper);
                        
                        if lookup_result != TokenType::Bareword {
                            // Update the first token with merged value and new type
                            self.token_vec[left].token_type = lookup_result;
                            // Update the value - store the original case version, not uppercase
                            let merged_bytes = merged_original.as_bytes();
                            let copy_len = merged_bytes.len().min(31); // Leave space for null terminator
                            self.token_vec[left].val[..copy_len].copy_from_slice(&merged_bytes[..copy_len]);
                            self.token_vec[left].len = copy_len;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            } {
                pos -= 1;
                self.stats_folds += 1;
                if left > 0 {
                    left -= 1;
                }
                continue;
            
            // FOLD: semicolon + function(IF) -> TSQL - from apply_two_token_fold  
            } else if self.token_vec[left].token_type == TokenType::Semicolon &&
                      self.token_vec[left + 1].token_type == TokenType::Function &&
                      self.token_vec[left + 1].len >= 2 &&
                      (self.token_vec[left + 1].val[0] == b'I' || self.token_vec[left + 1].val[0] == b'i') &&
                      (self.token_vec[left + 1].val[1] == b'F' || self.token_vec[left + 1].val[1] == b'f') {
                // IF is normally a function, except in Transact-SQL where it can be used as a standalone
                // control flow operator, e.g. ; IF 1=1 ... if found after a semicolon, convert from 'f' type to 'T' type
                self.token_vec[left + 1].token_type = TokenType::Tsql;
                continue;
            
            // FOLD: (bareword|variable) + leftparens -> function (for specific functions) - from apply_two_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Bareword ||
                       self.token_vec[left].token_type == TokenType::Variable) &&
                      self.token_vec[left + 1].token_type == TokenType::LeftParenthesis &&
                      {
                          let val = self.token_vec[left].value_as_str();
                          // TSQL functions but common enough to be column names
                          self.cstrcasecmp("USER_ID", val) == 0 ||
                          self.cstrcasecmp("USER_NAME", val) == 0 ||
                          // Function in MYSQL  
                          self.cstrcasecmp("DATABASE", val) == 0 ||
                          self.cstrcasecmp("PASSWORD", val) == 0 ||
                          self.cstrcasecmp("USER", val) == 0 ||
                          // Mysql words that act as a variable and are a function
                          // TSQL current_users is fake-variable
                          self.cstrcasecmp("CURRENT_USER", val) == 0 ||
                          self.cstrcasecmp("CURRENT_DATE", val) == 0 ||
                          self.cstrcasecmp("CURRENT_TIME", val) == 0 ||
                          self.cstrcasecmp("CURRENT_TIMESTAMP", val) == 0 ||
                          self.cstrcasecmp("LOCALTIME", val) == 0 ||
                          self.cstrcasecmp("LOCALTIMESTAMP", val) == 0
                      } {
                // pos is the same, other conversions need to go here... for instance
                // password CAN be a function, coalesce CAN be a function
                self.token_vec[left].token_type = TokenType::Function;
                continue;
            
            // FOLD: keyword IN/NOT_IN + leftparens -> operator, else -> bareword - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::Keyword &&
                      {
                          let val = self.token_vec[left].value_as_str();
                          self.cstrcasecmp("IN", val) == 0 || self.cstrcasecmp("NOT IN", val) == 0
                      } {
                if self.token_vec[left + 1].token_type == TokenType::LeftParenthesis {
                    // got .... IN ( ... (or 'NOT IN') - it's an operator
                    self.token_vec[left].token_type = TokenType::Operator;
                } else {
                    // it's a nothing
                    self.token_vec[left].token_type = TokenType::Bareword;
                }
                // "IN" can be used as "IN BOOLEAN MODE" for mysql in which case merging of words can be done later
                // otherwise it acts as an equality operator __ IN (values..)
                // here we got "IN" "(" so it's an operator.
                // also back track to handle "NOT IN"
                // might need to do the same with like
                // two use cases "foo" LIKE "BAR" (normal operator)
                // "foo" = LIKE(1,2)
                continue;
            
            // FOLD: operator LIKE/NOT_LIKE + leftparens -> function - from apply_two_token_fold
            // NOTE: This rule falls through in C - no continue!
            } else if self.token_vec[left].token_type == TokenType::Operator &&
                      {
                          let val = self.token_vec[left].value_as_str();
                          self.cstrcasecmp("LIKE", val) == 0 || self.cstrcasecmp("NOT LIKE", val) == 0
                      } {
                if self.token_vec[left + 1].token_type == TokenType::LeftParenthesis {
                    // SELECT LIKE(...  - it's a function
                    self.token_vec[left].token_type = TokenType::Function;
                }
                // NO continue here - falls through to next rule like C does
            
            // FOLD: sqltype + X -> X (remove sqltype) - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::SqlType &&
                      (self.token_vec[left + 1].token_type == TokenType::Bareword ||
                       self.token_vec[left + 1].token_type == TokenType::Number ||
                       self.token_vec[left + 1].token_type == TokenType::SqlType ||
                       self.token_vec[left + 1].token_type == TokenType::LeftParenthesis ||
                       self.token_vec[left + 1].token_type == TokenType::Function ||
                       self.token_vec[left + 1].token_type == TokenType::Variable ||
                       self.token_vec[left + 1].token_type == TokenType::String) {
                self.token_vec[left] = self.token_vec[left + 1].clone();
                pos -= 1;
                self.stats_folds += 1;
                left = 0;
                continue;
            
            // FOLD: collate + bareword -> handle collation types - from apply_two_token_fold
            // NOTE: This rule falls through in C - no continue!
            } else if self.token_vec[left].token_type == TokenType::Collate &&
                      self.token_vec[left + 1].token_type == TokenType::Bareword {
                // there are too many collation types.. so if the bareword has a "_" then it's TYPE_SQLTYPE
                let val = self.token_vec[left + 1].value_as_str();
                if val.contains('_') {
                    self.token_vec[left + 1].token_type = TokenType::SqlType;
                    left = 0;
                }
                // NO continue here - falls through like C does
            
            // FOLD: backslash + arithmetic_op -> number, else copy - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::Backslash {
                if self.is_arithmetic_op(&self.token_vec[left + 1]) {
                    // very weird case in TSQL where '\%1' is parsed as '0 % 1', etc
                    self.token_vec[left].token_type = TokenType::Number;
                } else {
                    // just ignore it.. Again T-SQL seems to parse \1 as "1"
                    self.token_vec[left] = self.token_vec[left + 1].clone();
                    pos -= 1;
                    self.stats_folds += 1;
                }
                left = 0;
                continue;
            
            // FOLD: leftparens + leftparens -> leftparens - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::LeftParenthesis &&
                      self.token_vec[left + 1].token_type == TokenType::LeftParenthesis {
                pos -= 1;
                left = 0;
                self.stats_folds += 1;
                continue;
            
            // FOLD: rightparens + rightparens -> rightparens - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::RightParenthesis &&
                      self.token_vec[left + 1].token_type == TokenType::RightParenthesis {
                pos -= 1;
                left = 0;
                self.stats_folds += 1;
                continue;
            
            // FOLD: leftbrace + bareword -> special handling - from apply_two_token_fold
            } else if self.token_vec[left].token_type == TokenType::LeftBrace &&
                      self.token_vec[left + 1].token_type == TokenType::Bareword {
                // MySQL Degenerate case -- 
                // select { ``.``.id };  -- valid !!!
                // select { ``.``.``.id };  -- invalid
                // select ``.``.id; -- invalid
                // select { ``.id }; -- invalid
                // so it appears {``.``.id} is a magic case
                // I suspect this is "current database, current table, field id"
                // The folding code can't look at more than 3 tokens, and I don't want to make two passes.
                // Since "{ ``" so rare, we are just going to blacklist it.
                // Highly likely this will need revisiting!
                if self.token_vec[left + 1].len == 0 {
                    self.token_vec[left + 1].token_type = TokenType::Evil;
                    // Copy tokens before early return
                    self.tokens.clear();
                    for i in 0..(left + 2) {
                        self.tokens.push(self.token_vec[i].clone());
                    }
                    return left + 2;
                }
                // weird ODBC / MYSQL {foo expr} --> expr
                // but for this rule we just strip away the "{ foo" part
                left = 0;
                pos -= 2;
                self.stats_folds += 2;
                continue;
            
            // FOLD: X + rightbrace -> X - from apply_two_token_fold
            } else if self.token_vec[left + 1].token_type == TokenType::RightBrace {
                pos -= 1;
                left = 0;
                self.stats_folds += 1;
                continue;
            }
            
            // all cases of handling 2 tokens is done and nothing matched. Get one more token
            while more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && pos - left < 3 {
                if let Some(token) = tokenizer.next_token() {
                    // Count all tokens processed for stats_tokens
                    self.stats_tokens += 1;
                    
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
            
            /* ALL 3-TOKEN FOLDING RULES - exactly matching C implementation with else-if chain */
            
            // FOLD: number operator number -> number - from apply_three_token_fold
            if self.token_vec[left].token_type == TokenType::Number &&
               self.token_vec[left + 1].token_type == TokenType::Operator &&
               self.token_vec[left + 2].token_type == TokenType::Number {
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: operator X operator -> operator (where X != leftparens) - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Operator &&
                      self.token_vec[left + 1].token_type != TokenType::LeftParenthesis &&
                      self.token_vec[left + 2].token_type == TokenType::Operator {
                left = 0;
                pos -= 2;
                continue;
            
            // FOLD: logic_operator X logic_operator -> logic_operator - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::LogicOperator &&
                      self.token_vec[left + 2].token_type == TokenType::LogicOperator {
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: variable operator (variable|number|bareword) -> variable - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Variable &&
                      self.token_vec[left + 1].token_type == TokenType::Operator &&
                      (self.token_vec[left + 2].token_type == TokenType::Variable ||
                       self.token_vec[left + 2].token_type == TokenType::Number ||
                       self.token_vec[left + 2].token_type == TokenType::Bareword) {
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: (bareword|number) operator (number|bareword) -> first - from apply_three_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Bareword ||
                       self.token_vec[left].token_type == TokenType::Number) &&
                      self.token_vec[left + 1].token_type == TokenType::Operator &&
                      (self.token_vec[left + 2].token_type == TokenType::Number ||
                       self.token_vec[left + 2].token_type == TokenType::Bareword) {
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: (bareword|number|string|variable) operator :: sqltype -> first (PostgreSQL casting) - from apply_three_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Bareword ||
                       self.token_vec[left].token_type == TokenType::Number ||
                       self.token_vec[left].token_type == TokenType::Variable ||
                       self.token_vec[left].token_type == TokenType::String) &&
                      self.token_vec[left + 1].token_type == TokenType::Operator &&
                      self.token_vec[left + 1].len == 2 && 
                      self.token_vec[left + 1].val[0] == b':' && 
                      self.token_vec[left + 1].val[1] == b':' &&
                      self.token_vec[left + 2].token_type == TokenType::SqlType {
                pos -= 2;
                left = 0;
                self.stats_folds += 2; // Only this 3-token rule increments stats_folds (by 2)
                continue;
            
            // FOLD: (bareword|number|string|variable) comma (number|bareword|string|variable) -> first_token - from apply_three_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Bareword ||
                       self.token_vec[left].token_type == TokenType::Number ||
                       self.token_vec[left].token_type == TokenType::String ||
                       self.token_vec[left].token_type == TokenType::Variable) &&
                      self.token_vec[left + 1].token_type == TokenType::Comma &&
                      (self.token_vec[left + 2].token_type == TokenType::Number ||
                       self.token_vec[left + 2].token_type == TokenType::Bareword ||
                       self.token_vec[left + 2].token_type == TokenType::String ||
                       self.token_vec[left + 2].token_type == TokenType::Variable) {
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: (expression|group|comma) + unary_op + leftparens -> remove unary - from apply_three_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Expression ||
                       self.token_vec[left].token_type == TokenType::Group ||
                       self.token_vec[left].token_type == TokenType::Comma) &&
                      self.is_unary_op(&self.token_vec[left + 1]) &&
                      self.token_vec[left + 2].token_type == TokenType::LeftParenthesis {
                // got something like SELECT + (, LIMIT + ( - remove unary operator
                self.token_vec[left + 1] = self.token_vec[left + 2].clone();
                pos -= 1;
                left = 0;
                continue;
            
            // FOLD: (keyword|expression|group) + unary_op + (number|bareword|variable|string|function) -> remove unary - from apply_three_token_fold
            } else if (self.token_vec[left].token_type == TokenType::Keyword ||
                       self.token_vec[left].token_type == TokenType::Expression ||
                       self.token_vec[left].token_type == TokenType::Group) &&
                      self.is_unary_op(&self.token_vec[left + 1]) &&
                      (self.token_vec[left + 2].token_type == TokenType::Number ||
                       self.token_vec[left + 2].token_type == TokenType::Bareword ||
                       self.token_vec[left + 2].token_type == TokenType::Variable ||
                       self.token_vec[left + 2].token_type == TokenType::String ||
                       self.token_vec[left + 2].token_type == TokenType::Function) {
                // remove unary operators - select - 1
                self.token_vec[left + 1] = self.token_vec[left + 2].clone();
                pos -= 1;
                left = 0;
                continue;
            
            // FOLD: comma + unary_op + (number|bareword|variable|string) -> remove unary, backup - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Comma &&
                      self.is_unary_op(&self.token_vec[left + 1]) &&
                      (self.token_vec[left + 2].token_type == TokenType::Number ||
                       self.token_vec[left + 2].token_type == TokenType::Bareword ||
                       self.token_vec[left + 2].token_type == TokenType::Variable ||
                       self.token_vec[left + 2].token_type == TokenType::String) {
                // interesting case turn ", -1" ->> ",1" PLUS we need to back up one token if possible 
                // to see if more folding can be done - "1,-1" --> "1"
                self.token_vec[left + 1] = self.token_vec[left + 2].clone();
                left = 0;
                // pos is >= 3 so this is safe
                if pos >= 3 {
                    pos -= 3;
                }
                continue;
            
            // FOLD: comma + unary_op + function -> remove unary only - from apply_three_token_fold  
            } else if self.token_vec[left].token_type == TokenType::Comma &&
                      self.is_unary_op(&self.token_vec[left + 1]) &&
                      self.token_vec[left + 2].token_type == TokenType::Function {
                // Separate case from above since you end up with
                // 1,-sin(1) --> 1 (1)
                // Here, just do
                // 1,-sin(1) --> 1,sin(1)
                // just remove unary operator
                self.token_vec[left + 1] = self.token_vec[left + 2].clone();
                pos -= 1;
                left = 0;
                continue;
            
            // FOLD: bareword . bareword -> bareword (database.table -> table) - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Bareword &&
                      self.token_vec[left + 1].token_type == TokenType::Dot &&
                      self.token_vec[left + 2].token_type == TokenType::Bareword {
                // ignore the '.n' - typically is this databasename.table
                pos -= 2;
                left = 0;
                continue;
            
            // FOLD: expression . bareword -> bareword (SELECT . `foo` -> SELECT `foo`) - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Expression &&
                      self.token_vec[left + 1].token_type == TokenType::Dot &&
                      self.token_vec[left + 2].token_type == TokenType::Bareword {
                // select . `foo` --> select `foo`
                self.token_vec[left + 1] = self.token_vec[left + 2].clone();
                pos -= 1;
                left = 0;
                continue;
            
            // FOLD: function + leftparens + (not rightparens) -> handle special functions - from apply_three_token_fold
            } else if self.token_vec[left].token_type == TokenType::Function &&
                      self.token_vec[left + 1].token_type == TokenType::LeftParenthesis &&
                      self.token_vec[left + 2].token_type != TokenType::RightParenthesis {
                // whats going on here
                // Some SQL functions like USER() have 0 args
                // if we get User(foo), then User is not a function
                // This should be expanded since it eliminated a lot of false positives.
                let val = self.token_vec[left].value_as_str();
                if self.cstrcasecmp("USER", val) == 0 {
                    self.token_vec[left].token_type = TokenType::Bareword;
                }
                // NOTE: C version falls through here - no continue
            }
            
            // no folding -- assume left-most token is good, now use the existing 2 tokens -- do not get another
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
        
        // Add last comment back to token array if there's space (matches C lines 1873-1877)
        if left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.token_type == TokenType::Comment {
            self.token_vec[left] = last_comment.clone();
            self.tokens.push(last_comment);
            left += 1;
        }
        
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
            3 => self.cstrcasecmp("NOT", val) == 0,
            _ => false,
        }
    }
    
    fn is_arithmetic_op(&self, token: &Token) -> bool {
        if token.token_type != TokenType::Operator || token.len != 1 {
            return false;
        }
        
        let ch = token.val[0] as char;
        matches!(ch, '*' | '/' | '-' | '+' | '%')
    }
    
    /// Case-insensitive string comparison that matches C's cstrcasecmp exactly
    fn cstrcasecmp(&self, a: &str, b: &str) -> i32 {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        let n = a_bytes.len();
        
        if n != b_bytes.len() {
            return if a_bytes.len() < b_bytes.len() { -1 } else { 1 };
        }
        
        for i in 0..n {
            let mut cb = b_bytes[i];
            if cb >= b'a' && cb <= b'z' {
                cb -= 0x20;
            }
            if a_bytes[i] != cb {
                return a_bytes[i] as i32 - cb as i32;
            } else if a_bytes[i] == 0 {
                return -1;
            }
        }
        
        if n == 0 { 0 } else { 0 }
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
    
    /// Checks if a token contains MySQL conditional comment patterns (/*!)
    /// This matches the C implementation's logic for detecting evil comment patterns
    /// 
    /// C code reference: libinjection_sqli.c lines 454-474 (is_mysql_comment function)
    /// Also referenced: libinjection_sqli.c lines 513-514 (parse_slash calling is_mysql_comment)
    fn has_mysql_conditional_comment(&self, token: &Token) -> bool {
        if token.len < 3 {
            return false;
        }
        
        // Look for /*!  pattern in token content
        // This matches C's is_mysql_comment function logic:
        // C: if (cs[pos + 2] != '!') return 0;  (line 464)
        let content = &token.val[..token.len.min(32)];
        
        for i in 0..content.len().saturating_sub(2) {
            if content[i] == b'/' && content[i + 1] == b'*' && content[i + 2] == b'!' {
                return true;
            }
        }
        
        false
    }
    
    /// Post-process tokens to detect MySQL conditional comments in string content
    /// This matches the C implementation's behavior where string content is scanned
    /// for evil patterns and converted to EVIL tokens
    /// 
    /// C code reference: libinjection_sqli.c lines 1942-1954 (fingerprint post-processing)
    /// The C code checks: if (strchr(sql_state->fingerprint, TYPE_EVIL))
    /// and then sets: sql_state->fingerprint[0] = TYPE_EVIL; (line 1949)
    fn detect_mysql_comments_in_tokens(&mut self, token_count: usize) {
        for i in 0..token_count.min(self.tokens.len()) {
            // Check if this is a string token containing MySQL conditional comment
            if self.tokens[i].token_type == TokenType::String {
                if self.has_mysql_conditional_comment(&self.tokens[i]) {
                    // Convert to EVIL token like C does
                    // C: sql_state->tokenvec[0].type = TYPE_EVIL; (line 1951)
                    self.tokens[i].token_type = TokenType::Evil;
                }
            }
        }
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
        
        // Handle Evil tokens exactly like C implementation
        // If any Evil token ('X') is present in the fingerprint, clear everything
        // and set the fingerprint to just 'X' to match C behavior
        let fingerprint_slice = &self.fingerprint[..8];
        if fingerprint_slice.contains(&b'X') {
            // Clear the entire fingerprint and token vector
            self.fingerprint = [0; 8];
            self.fingerprint[0] = b'X';
            
            // Reset the token vector to contain just the Evil token
            // to match C's behavior of clearing tokenvec and setting first token to Evil
            if !self.tokens.is_empty() {
                self.tokens.clear();
                let mut val = [0u8; 32];
                val[0] = b'X';
                self.tokens.push(Token {
                    token_type: TokenType::Evil,
                    pos: 0,
                    len: 1,
                    val,
                    str_open: 0,
                    str_close: 0,
                    count: 0,
                });
            }
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
        
        // If second token starts with '#' ignore - too many false positives
        // This matches C behavior at libinjection_sqli.c:2078
        if !self.tokens[1].val.is_empty() && self.tokens[1].val[0] == b'#' {
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
                // This matches C behavior at libinjection_sqli.c:2169-2177
                return true;
            }
            
            if self.stats_tokens == 3 {
                // This matches C behavior at libinjection_sqli.c:2179-2181
                return false;
            }
            
            // Not SQLi
            // This matches C behavior at libinjection_sqli.c:2187-2188
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
            // If stats_tokens != 3, this means there's folding or more complex patterns
            // Continue with default behavior (return true at end of function)
        }
        
        // More whitelist rules...
        
        true
    }
}

// Re-export tokenizer types
pub use tokenizer::{Token, TokenType, SqliTokenizer};

mod tokenizer;
mod blacklist;
pub mod sqli_data;

// Import CHAR_NULL for internal use
use tokenizer::CHAR_NULL;

#[cfg(test)]
mod tests;