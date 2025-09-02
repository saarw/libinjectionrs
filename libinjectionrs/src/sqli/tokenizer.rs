// SQL tokenizer implementation matching libinjection C version

use crate::sqli::{SqliFlags, sqli_data};

// Token type constants matching C version
const TYPE_NONE: u8 = 0;
const TYPE_KEYWORD: u8 = b'k';
const TYPE_UNION: u8 = b'U';
const TYPE_GROUP: u8 = b'B';
const TYPE_EXPRESSION: u8 = b'E';
const TYPE_SQLTYPE: u8 = b't';
const TYPE_FUNCTION: u8 = b'f';
const TYPE_BAREWORD: u8 = b'n';
const TYPE_NUMBER: u8 = b'1';
const TYPE_VARIABLE: u8 = b'v';
const TYPE_STRING: u8 = b's';
const TYPE_OPERATOR: u8 = b'o';
const TYPE_LOGIC_OPERATOR: u8 = b'&';
const TYPE_COMMENT: u8 = b'c';
const TYPE_COLLATE: u8 = b'A';
const TYPE_LEFTPARENS: u8 = b'(';
const TYPE_RIGHTPARENS: u8 = b')';
const TYPE_LEFTBRACE: u8 = b'{';
const TYPE_RIGHTBRACE: u8 = b'}';
const TYPE_DOT: u8 = b'.';
const TYPE_COMMA: u8 = b',';
const TYPE_COLON: u8 = b':';
const TYPE_SEMICOLON: u8 = b';';
const TYPE_TSQL: u8 = b'T';
const TYPE_UNKNOWN: u8 = b'?';
const TYPE_EVIL: u8 = b'X';
const TYPE_FINGERPRINT: u8 = b'F';
const TYPE_BACKSLASH: u8 = b'\\';

// Character constants
pub(crate) const CHAR_NULL: u8 = b'\0';
const CHAR_SINGLE: u8 = b'\'';
const CHAR_DOUBLE: u8 = b'"';
const CHAR_TICK: u8 = b'`';

// SQL injection limits
const LIBINJECTION_SQLI_TOKEN_SIZE: usize = 32;

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
    Number,
    Variable,
    String,
    Operator,
    LogicOperator,
    Comment,
    Collate,
    LeftParenthesis,
    RightParenthesis,
    LeftBrace,
    RightBrace,
    Dot,
    Comma,
    Colon,
    Semicolon,
    Tsql,
    Unknown,
    Evil,
    Fingerprint,
    Backslash,
}

impl TokenType {
    pub fn to_char(&self) -> char {
        match self {
            TokenType::None => '\0',
            TokenType::Keyword => 'k',
            TokenType::Union => 'U',
            TokenType::Group => 'B',
            TokenType::Expression => 'E',
            TokenType::SqlType => 't',
            TokenType::Function => 'f',
            TokenType::Bareword => 'n',
            TokenType::Number => '1',
            TokenType::Variable => 'v',
            TokenType::String => 's',
            TokenType::Operator => 'o',
            TokenType::LogicOperator => '&',
            TokenType::Comment => 'c',
            TokenType::Collate => 'A',
            TokenType::LeftParenthesis => '(',
            TokenType::RightParenthesis => ')',
            TokenType::LeftBrace => '{',
            TokenType::RightBrace => '}',
            TokenType::Dot => '.',
            TokenType::Comma => ',',
            TokenType::Colon => ':',
            TokenType::Semicolon => ';',
            TokenType::Tsql => 'T',
            TokenType::Unknown => '?',
            TokenType::Evil => 'X',
            TokenType::Fingerprint => 'F',
            TokenType::Backslash => '\\',
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub pos: usize,
    pub len: usize,
    pub val: [u8; 32],
    pub str_open: u8,
    pub str_close: u8,
    pub count: i32,
}

impl Token {
    pub fn new() -> Self {
        Self {
            token_type: TokenType::None,
            pos: 0,
            len: 0,
            val: [0; 32],
            str_open: CHAR_NULL,
            str_close: CHAR_NULL,
            count: 0,
        }
    }
    
    pub fn value_as_str(&self) -> &str {
        let end = self.len.min(32);
        std::str::from_utf8(&self.val[..end]).unwrap_or("")
    }
    
    pub fn clear(&mut self) {
        *self = Self::new();
    }
    
    pub fn assign_char(&mut self, token_type: u8, pos: usize, value: u8) {
        self.token_type = byte_to_token_type(token_type);
        self.pos = pos;
        self.len = 1;
        self.val[0] = value;
        self.val[1] = CHAR_NULL;
        // Note: str_open, str_close, and count are NOT reset to preserve variable info like C st_assign_char()
    }
    
    pub fn assign(&mut self, token_type: u8, pos: usize, len: usize, value: &[u8]) {
        let copy_len = len.min(LIBINJECTION_SQLI_TOKEN_SIZE - 1);
        let actual_copy_len = copy_len.min(value.len());
        self.token_type = byte_to_token_type(token_type);
        self.pos = pos;
        self.len = actual_copy_len;
        
        // Clear the value array first
        self.val = [0; 32];
        
        // Copy the value
        for i in 0..actual_copy_len {
            self.val[i] = value[i];
        }
        
        self.val[actual_copy_len] = CHAR_NULL;
        // Note: str_open, str_close, and count are NOT reset to preserve variable info like C st_assign()
    }
    
    pub fn copy_from(&mut self, other: &Token) {
        *self = other.clone();
    }
}

fn byte_to_token_type(b: u8) -> TokenType {
    match b {
        TYPE_KEYWORD => TokenType::Keyword,
        TYPE_UNION => TokenType::Union,
        TYPE_GROUP => TokenType::Group,
        TYPE_EXPRESSION => TokenType::Expression,
        TYPE_SQLTYPE => TokenType::SqlType,
        TYPE_FUNCTION => TokenType::Function,
        TYPE_BAREWORD => TokenType::Bareword,
        TYPE_NUMBER => TokenType::Number,
        TYPE_VARIABLE => TokenType::Variable,
        TYPE_STRING => TokenType::String,
        TYPE_OPERATOR => TokenType::Operator,
        TYPE_LOGIC_OPERATOR => TokenType::LogicOperator,
        TYPE_COMMENT => TokenType::Comment,
        TYPE_COLLATE => TokenType::Collate,
        TYPE_LEFTPARENS => TokenType::LeftParenthesis,
        TYPE_RIGHTPARENS => TokenType::RightParenthesis,
        TYPE_LEFTBRACE => TokenType::LeftBrace,
        TYPE_RIGHTBRACE => TokenType::RightBrace,
        TYPE_DOT => TokenType::Dot,
        TYPE_COMMA => TokenType::Comma,
        TYPE_COLON => TokenType::Colon,
        TYPE_SEMICOLON => TokenType::Semicolon,
        TYPE_TSQL => TokenType::Tsql,
        TYPE_UNKNOWN => TokenType::Unknown,
        TYPE_EVIL => TokenType::Evil,
        TYPE_FINGERPRINT => TokenType::Fingerprint,
        TYPE_BACKSLASH => TokenType::Backslash,
        _ => TokenType::None,
    }
}

fn token_type_to_byte(t: TokenType) -> u8 {
    match t {
        TokenType::Keyword => TYPE_KEYWORD,
        TokenType::Union => TYPE_UNION,
        TokenType::Group => TYPE_GROUP,
        TokenType::Expression => TYPE_EXPRESSION,
        TokenType::SqlType => TYPE_SQLTYPE,
        TokenType::Function => TYPE_FUNCTION,
        TokenType::Bareword => TYPE_BAREWORD,
        TokenType::Number => TYPE_NUMBER,
        TokenType::Variable => TYPE_VARIABLE,
        TokenType::String => TYPE_STRING,
        TokenType::Operator => TYPE_OPERATOR,
        TokenType::LogicOperator => TYPE_LOGIC_OPERATOR,
        TokenType::Comment => TYPE_COMMENT,
        TokenType::Collate => TYPE_COLLATE,
        TokenType::LeftParenthesis => TYPE_LEFTPARENS,
        TokenType::RightParenthesis => TYPE_RIGHTPARENS,
        TokenType::LeftBrace => TYPE_LEFTBRACE,
        TokenType::RightBrace => TYPE_RIGHTBRACE,
        TokenType::Dot => TYPE_DOT,
        TokenType::Comma => TYPE_COMMA,
        TokenType::Colon => TYPE_COLON,
        TokenType::Semicolon => TYPE_SEMICOLON,
        TokenType::Tsql => TYPE_TSQL,
        TokenType::Unknown => TYPE_UNKNOWN,
        TokenType::Evil => TYPE_EVIL,
        TokenType::Fingerprint => TYPE_FINGERPRINT,
        TokenType::Backslash => TYPE_BACKSLASH,
        _ => TYPE_NONE,
    }
}

// Lookup function type
type LookupFn = dyn Fn(&str) -> TokenType;

pub struct SqliTokenizer<'a> {
    input: &'a [u8],
    flags: SqliFlags,
    pos: usize,
    current: Token,
    lookup_fn: Option<&'a LookupFn>,
    pub stats_comment_c: i32,
    pub stats_comment_ddw: i32,
    pub stats_comment_ddx: i32,
    pub stats_comment_hash: i32,
}

impl<'a> SqliTokenizer<'a> {
    pub fn new(input: &'a [u8], flags: SqliFlags) -> Self {
        Self {
            input,
            flags,
            pos: 0,
            current: Token::new(),
            lookup_fn: None,
            stats_comment_c: 0,
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_hash: 0,
        }
    }
    
    pub fn with_lookup_fn(mut self, lookup_fn: &'a LookupFn) -> Self {
        self.lookup_fn = Some(lookup_fn);
        self
    }
    
    fn lookup_word(&self, word: &str) -> TokenType {
        if let Some(lookup_fn) = self.lookup_fn {
            lookup_fn(word)
        } else {
            sqli_data::lookup_word(word)
        }
    }
    
    // Main tokenization function - matches libinjection_sqli_tokenize
    pub fn next_token(&mut self) -> Option<Token> {
        if self.input.is_empty() || self.pos >= self.input.len() {
            return None;
        }
        
        self.current.clear();
        
        // Handle quote context at start of string - matches C behavior
        let quote_context = self.flags.quote_context();
        if self.pos == 0 && quote_context != b'\0' {
            // FIXED: Parse only first token as string like C does with parse_string_core
            return self.parse_first_token_with_quote_context(quote_context);
        }
        
        while self.pos < self.input.len() {
            let ch = self.input[self.pos];
            let new_pos = self.dispatch_char_parser(ch);
            self.pos = new_pos;
            
            if self.current.token_type != TokenType::None {
                return Some(self.current.clone());
            }
        }
        
        None
    }
    
    fn parse_first_token_with_quote_context(&mut self, quote_char: u8) -> Option<Token> {
        // FIXED: This matches C's parse_string_core behavior exactly
        // C call: parse_string_core(s, slen, 0, current, flag2delim(sf->flags), 0);
        // Parameters: input, len, pos=0, token, delimiter, offset=0
        // 
        // IMPORTANT: Even when offset=0 (simulated quote), C still checks for escape sequences
        // like double-delimiter ("") and backslash escapes. This is crucial for matching C behavior.
        
        let start_pos = self.pos; // Should be 0 for first token
        
        // Find first unescaped occurrence of quote_char (matching C's logic)
        let mut quote_pos = None;
        let mut search_pos = start_pos;
        
        while search_pos < self.input.len() {
            if self.input[search_pos] == quote_char {
                // Check if this quote is escaped - C does this even for simulated quotes!
                if self.is_double_delim_escaped(search_pos) {
                    // Skip escaped quote pair
                    search_pos += 2;
                    continue;
                } else if search_pos > start_pos && self.is_backslash_escaped(search_pos - 1) {
                    // Skip backslash escaped quote
                    search_pos += 1;
                    continue;
                } else {
                    // Found unescaped quote
                    quote_pos = Some(search_pos);
                    break;
                }
            }
            search_pos += 1;
        }
        
        // Set string open/close info like C does
        // offset = 0 means simulated quote, so str_open = CHAR_NULL
        self.current.str_open = CHAR_NULL;
        
        if let Some(end_pos) = quote_pos {
            // Found closing quote - parse up to that point
            let content = &self.input[start_pos..end_pos];
            self.current.assign(TYPE_STRING, start_pos, end_pos - start_pos, content);
            self.current.str_close = quote_char;
            self.pos = end_pos + 1; // Skip the closing quote
        } else {
            // No closing quote found - parse entire remaining input
            let content = &self.input[start_pos..];
            self.current.assign(TYPE_STRING, start_pos, self.input.len() - start_pos, content);
            self.current.str_close = CHAR_NULL;
            self.pos = self.input.len();
        }
        
        Some(self.current.clone())
    }
    
    // Character dispatch function - matches char_parse_map in C
    fn dispatch_char_parser(&mut self, ch: u8) -> usize {
        use crate::sqli::sqli_data::{get_char_type, CharType};
        
        // Use the generated lookup table - same as C implementation
        match get_char_type(ch) {
            CharType::White => self.parse_white(),
            CharType::Bang => self.parse_operator2(),
            CharType::String => self.parse_string(),
            CharType::Hash => self.parse_hash(),
            CharType::Money => self.parse_money(),
            CharType::Op1 | CharType::Unary => self.parse_operator1(),
            CharType::Op2 => self.parse_operator2(),
            CharType::LeftParens | CharType::RightParens | CharType::Comma | 
            CharType::Semicolon | CharType::LeftBrace | CharType::RightBrace => self.parse_char(),
            CharType::Dash => self.parse_dash(),
            CharType::Number => self.parse_number(),
            CharType::Slash => self.parse_slash(),
            CharType::Variable => self.parse_var(),
            CharType::Word => self.parse_word(),     // This now handles UTF-8 bytes 128-255!
            CharType::BString => self.parse_bstring(),
            CharType::EString => self.parse_estring(),
            CharType::NQString => self.parse_nqstring(),
            CharType::QString => self.parse_qstring(),
            CharType::UString => self.parse_ustring(),
            CharType::XString => self.parse_xstring(),
            CharType::BWord => self.parse_bword(),
            CharType::Backslash => self.parse_backslash(),
            CharType::Tick => self.parse_tick(),
            CharType::Other => self.parse_other(),
        }
    }
    
    // Parser implementations matching C version exactly
    
    fn parse_white(&mut self) -> usize {
        self.pos + 1
    }
    
    fn parse_operator1(&mut self) -> usize {
        let ch = self.input[self.pos];
        self.current.assign_char(TYPE_OPERATOR, self.pos, ch);
        self.pos + 1
    }
    
    fn parse_operator2(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Boundary check - if not enough characters for 2-char operator, fallback
        if pos + 1 >= slen {
            return self.parse_operator1();
        }
        
        // First check for 3-character operator <=> (special case in C)
        if pos + 2 < slen && 
           self.input[pos] == b'<' && self.input[pos + 1] == b'=' && self.input[pos + 2] == b'>' {
            let op = [b'<', b'=', b'>'];
            self.current.assign(TYPE_OPERATOR, pos, 3, &op);
            return pos + 3;
        }
        
        // Try 2-character operator lookup using the comprehensive table
        let two_char = &self.input[pos..pos + 2];
        if let Ok(two_char_str) = std::str::from_utf8(two_char) {
            let token_type = self.lookup_word(two_char_str);
            if token_type != TokenType::None && token_type != TokenType::Bareword {
                // Found a 2-character operator in the lookup table
                let type_byte = match token_type {
                    TokenType::Operator => TYPE_OPERATOR,
                    TokenType::LogicOperator => TYPE_LOGIC_OPERATOR,
                    _ => TYPE_OPERATOR, // Default fallback
                };
                self.current.assign(type_byte, pos, 2, two_char);
                return pos + 2;
            }
        }
        
        // No 2-character operator found, check for special single character cases
        let ch = self.input[pos];
        if ch == b':' {
            // Special case: ':' is not an operator, it's TYPE_COLON
            self.current.assign_char(TYPE_COLON, pos, ch);
            return pos + 1;
        } else {
            // Must be a single char operator - delegate to parse_operator1
            return self.parse_operator1();
        }
    }
    
    fn parse_other(&mut self) -> usize {
        let ch = self.input[self.pos];
        self.current.assign_char(TYPE_UNKNOWN, self.pos, ch);
        self.pos + 1
    }
    
    fn parse_char(&mut self) -> usize {
        let ch = self.input[self.pos];
        self.current.assign_char(ch, self.pos, ch);
        self.pos + 1
    }
    
    fn parse_hash(&mut self) -> usize {
        self.stats_comment_hash += 1;
        if self.flags.is_mysql() {
            // C version has a bug that increments stats_comment_hash twice in MySQL mode
            // We need to match this behavior exactly
            self.stats_comment_hash += 1;
            self.parse_eol_comment()
        } else {
            self.current.assign_char(TYPE_OPERATOR, self.pos, b'#');
            self.pos + 1
        }
    }
    
    fn parse_dash(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        if pos + 1 < slen && self.input[pos + 1] == b'-' {
            if pos + 2 >= slen || self.is_white_char(self.input[pos + 2]) {
                // "--" followed by whitespace or end: SQL comment
                self.stats_comment_ddw += 1;
                return self.parse_eol_comment();
            } else {
                // "--" followed by non-whitespace: depends on SQL mode
                self.stats_comment_ddx += 1;
                if self.flags.is_ansi() {
                    return self.parse_eol_comment();
                } else {
                    // MySQL treats as two unary operators
                    self.current.assign_char(TYPE_OPERATOR, pos, b'-');
                    return pos + 1;
                }
            }
        } else {
            // Single dash: operator
            self.current.assign_char(TYPE_OPERATOR, pos, b'-');
            pos + 1
        }
    }
    
    fn parse_slash(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Match C logic exactly: if (pos1 == slen || cs[pos1] != '*')
        if pos + 1 == slen || self.input[pos + 1] != b'*' {
            // Regular operator
            self.current.assign_char(TYPE_OPERATOR, pos, b'/');
            pos + 1
        } else {
            // C-style comment /* ... */
            self.stats_comment_c += 1;
            self.parse_c_comment()
        }
    }
    
    fn parse_backslash(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Weird MySQL alias for NULL, "\N" (capital N only)
        if pos + 1 < slen && self.input[pos + 1] == b'N' {
            let content = &self.input[pos..pos + 2];
            self.current.assign(TYPE_NUMBER, pos, 2, content);
            pos + 2
        } else {
            let ch = self.input[pos];
            self.current.assign_char(TYPE_BACKSLASH, pos, ch);
            pos + 1
        }
    }
    
    fn parse_eol_comment(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Find end of line or end of string
        let mut end_pos = pos;
        while end_pos < slen && self.input[end_pos] != b'\n' {
            end_pos += 1;
        }
        
        let comment_slice = &self.input[pos..end_pos];
        self.current.assign(TYPE_COMMENT, pos, end_pos - pos, comment_slice);
        
        if end_pos < slen {
            end_pos + 1 // Skip the newline
        } else {
            slen
        }
    }
    
    // Helper function equivalent to C memchr2: finds two consecutive characters
    fn memchr2(&self, haystack: &[u8], c0: u8, c1: u8) -> Option<usize> {
        if haystack.len() < 2 {
            return None;
        }
        
        for i in 0..haystack.len() - 1 {
            if haystack[i] == c0 && haystack[i + 1] == c1 {
                return Some(i);
            }
        }
        None
    }
    
    // Helper function equivalent to C is_mysql_comment
    fn is_mysql_comment(&self, pos: usize) -> bool {
        let slen = self.input.len();
        
        // Need at least 3 chars: /*!
        if pos + 2 >= slen {
            return false;
        }
        
        // Check if it's /*!
        self.input[pos] == b'/' && 
        self.input[pos + 1] == b'*' && 
        self.input[pos + 2] == b'!'
    }
    
    fn parse_c_comment(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // This implements the exact same logic as C parse_slash function
        
        // Search for */ in the part after /*
        let search_slice = if pos + 2 < slen {
            &self.input[pos + 2..]
        } else {
            &[]
        };
        
        let clen = if let Some(close_pos) = self.memchr2(search_slice, b'*', b'/') {
            // Found */: include everything from /* to */
            (pos + 2) + close_pos + 2 - pos  // +2 to include the */
        } else {
            // No */ found: include everything to end of string
            slen - pos
        };
        
        let mut ctype = TYPE_COMMENT;
        
        // Check for nested comments - matching C logic exactly, including the off-by-one bug
        // C code: memchr2(cur + 2, (size_t)(ptr - (cur + 1)), '/', '*')
        // where ptr points to the '*' in the closing '*/'
        if let Some(close_pos) = self.memchr2(search_slice, b'*', b'/') {
            // In C terms:
            // - cur = pos (start of /*)
            // - ptr = pos + 2 + close_pos (points to * in */)
            // - Search start: cur + 2 = pos + 2 
            // - Search length: ptr - (cur + 1) = (pos + 2 + close_pos) - (pos + 1) = close_pos + 1
            // The bug: should be ptr - (cur + 2) = close_pos, but it's close_pos + 1
            
            // So we search 1 byte more than we should
            let buggy_search_length = close_pos + 1;
            
            // Make sure we don't go out of bounds
            let actual_search_length = buggy_search_length.min(search_slice.len());
            
            if actual_search_length > 0 {
                let buggy_search_region = &search_slice[..actual_search_length];
                if self.memchr2(buggy_search_region, b'/', b'*').is_some() {
                    ctype = TYPE_EVIL;
                }
            }
        }
        
        // Check for MySQL conditional comments /*!
        if self.is_mysql_comment(pos) {
            ctype = TYPE_EVIL;
        }
        
        let comment_slice = &self.input[pos..pos + clen];
        self.current.assign(ctype, pos, clen, comment_slice);
        pos + clen
    }
    
    fn parse_string(&mut self) -> usize {
        let pos = self.pos;
        let delim = self.input[pos];
        self.parse_string_core(pos, delim, 1)
    }
    
    fn parse_string_core(&mut self, pos: usize, delim: u8, offset: usize) -> usize {
        let slen = self.input.len();
        let start_pos = pos + offset;
        let mut end_pos = start_pos;
        
        // Look for closing delimiter
        while end_pos < slen {
            if let Some(found_pos) = self.memchr(delim, &self.input[end_pos..]) {
                let actual_pos = end_pos + found_pos;
                
                // Check for escape sequences
                if actual_pos > 0 && self.is_backslash_escaped(actual_pos - 1) {
                    end_pos = actual_pos + 1;
                    continue;
                } else if self.is_double_delim_escaped(actual_pos) {
                    end_pos = actual_pos + 2;
                    continue;
                } else {
                    // Found unescaped closing delimiter
                    let content = &self.input[start_pos..actual_pos];
                    self.current.assign(TYPE_STRING, start_pos, actual_pos - start_pos, content);
                    self.current.str_open = delim;
                    self.current.str_close = delim;
                    return actual_pos + 1;
                }
            } else {
                // No closing delimiter found
                let content = &self.input[start_pos..];
                self.current.assign(TYPE_STRING, start_pos, slen - start_pos, content);
                self.current.str_open = delim;
                self.current.str_close = CHAR_NULL;
                return slen;
            }
        }
        
        // Handle unterminated string at end of input (like C does)
        let content = &self.input[start_pos..];
        self.current.assign(TYPE_STRING, start_pos, slen - start_pos, content);
        self.current.str_open = delim;
        self.current.str_close = CHAR_NULL;
        
        slen
    }
    
    fn parse_estring(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        if pos + 2 >= slen || self.input[pos + 1] != CHAR_SINGLE {
            return self.parse_word();
        }
        
        self.parse_string_core(pos, CHAR_SINGLE, 2)
    }
    
    fn parse_ustring(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        if pos + 2 < slen && self.input[pos + 1] == b'&' && self.input[pos + 2] == b'\'' {
            let _old_pos = self.pos;
            self.pos += 2;
            let result = self.parse_string();
            self.current.str_open = b'u';
            if self.current.str_close == b'\'' {
                self.current.str_close = b'u';
            }
            result
        } else {
            self.parse_word()
        }
    }
    
    fn parse_qstring(&mut self) -> usize {
        self.parse_qstring_core(0)
    }
    
    fn parse_nqstring(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        if pos + 2 < slen && self.input[pos + 1] == CHAR_SINGLE {
            return self.parse_estring();
        }
        
        self.parse_qstring_core(1)
    }
    
    fn parse_qstring_core(&mut self, offset: usize) -> usize {
        let pos = self.pos + offset;
        let slen = self.input.len();
        
        // Oracle Q-string: Q'<delimiter>content<delimiter>'
        if pos >= slen || (self.input[pos] != b'q' && self.input[pos] != b'Q') ||
           pos + 2 >= slen || self.input[pos + 1] != b'\'' {
            return self.parse_word();
        }
        
        let start_delim = self.input[pos + 2];
        if start_delim < 33 {
            return self.parse_word();
        }
        
        // Map opening to closing delimiter
        let end_delim = match start_delim {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            _ => start_delim,
        };
        
        // Find ending pattern
        let content_start = pos + 3;
        if let Some(end_pos) = self.find_qstring_end(content_start, end_delim) {
            let content = &self.input[content_start..end_pos];
            self.current.assign(TYPE_STRING, content_start, end_pos - content_start, content);
            self.current.str_open = b'q';
            self.current.str_close = b'q';
            end_pos + 2
        } else {
            let content = &self.input[content_start..];
            self.current.assign(TYPE_STRING, content_start, slen - content_start, content);
            self.current.str_open = b'q';
            self.current.str_close = CHAR_NULL;
            slen
        }
    }
    
    fn parse_bstring(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Binary string: B'01011'
        if pos + 2 >= slen || self.input[pos + 1] != b'\'' {
            return self.parse_word();
        }
        
        let content_start = pos + 2;
        let mut content_end = content_start;
        
        // Only allow 0 and 1
        while content_end < slen && (self.input[content_end] == b'0' || self.input[content_end] == b'1') {
            content_end += 1;
        }
        
        if content_end >= slen || self.input[content_end] != b'\'' {
            return self.parse_word();
        }
        
        let full_token = &self.input[pos..content_end + 1];
        self.current.assign(TYPE_NUMBER, pos, content_end + 1 - pos, full_token);
        content_end + 1
    }
    
    fn parse_xstring(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Hex string: X'deadbeef'
        if pos + 2 >= slen || self.input[pos + 1] != b'\'' {
            return self.parse_word();
        }
        
        let content_start = pos + 2;
        let mut content_end = content_start;
        
        // Only allow hex digits
        while content_end < slen {
            match self.input[content_end] {
                b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => content_end += 1,
                _ => break,
            }
        }
        
        if content_end >= slen || self.input[content_end] != b'\'' {
            return self.parse_word();
        }
        
        let full_token = &self.input[pos..content_end + 1];
        self.current.assign(TYPE_NUMBER, pos, content_end + 1 - pos, full_token);
        content_end + 1
    }
    
    fn parse_bword(&mut self) -> usize {
        let pos = self.pos;
        
        // SQL Server bracket words: [column name]
        if let Some(end_pos) = self.memchr(b']', &self.input[pos..]) {
            let actual_end = pos + end_pos;
            let content = &self.input[pos..=actual_end];
            self.current.assign(TYPE_BAREWORD, pos, content.len(), content);
            actual_end + 1
        } else {
            let content = &self.input[pos..];
            self.current.assign(TYPE_BAREWORD, pos, content.len(), content);
            self.input.len()
        }
    }
    
    fn parse_word(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // Find word boundary - matches C version's strlencspn character set
        let word_chars = b" []{}<>:\\?=@!#~+-*/&|^%(),';	\n\x0B\x0C\r\"\xA0\x00";
        let mut end_pos = pos;
        
        while end_pos < slen && !word_chars.contains(&self.input[end_pos]) {
            end_pos += 1;
        }
        
        let word_len = end_pos - pos;
        let word_slice = &self.input[pos..end_pos];
        
        self.current.assign(TYPE_BAREWORD, pos, word_len, word_slice);
        
        // Check for special delimiters within word
        for (i, &byte) in word_slice.iter().enumerate() {
            if byte == b'.' || byte == b'`' {
                let partial_word = std::str::from_utf8(&word_slice[..i]).unwrap_or("");
                let token_type = self.lookup_word(partial_word);
                if token_type != TokenType::None && token_type != TokenType::Bareword {
                    self.current.clear();
                    let type_byte = token_type_to_byte(token_type);
                    self.current.assign(type_byte, pos, i, &word_slice[..i]);
                    return pos + i;
                }
            }
        }
        
        // Do full word lookup
        if word_len < LIBINJECTION_SQLI_TOKEN_SIZE {
            let word_str = std::str::from_utf8(word_slice).unwrap_or("");
            let token_type = self.lookup_word(word_str);
            if token_type != TokenType::None {
                self.current.token_type = token_type;
            }
        }
        
        end_pos
    }
    
    fn parse_tick(&mut self) -> usize {
        // MySQL backticks
        let pos = self.parse_string_core(self.pos, CHAR_TICK, 1);
        
        // Check if backtick content is a keyword/function
        let word_str = std::str::from_utf8(&self.current.val[..self.current.len]).unwrap_or("");
        let token_type = self.lookup_word(word_str);
        
        if token_type == TokenType::Function {
            self.current.token_type = TokenType::Function;
        } else {
            self.current.token_type = TokenType::Bareword;
        }
        
        pos
    }
    
    fn parse_var(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        let mut new_pos = pos + 1;
        
        // Count @ symbols
        let mut at_count = 1;
        if new_pos < slen && self.input[new_pos] == b'@' {
            new_pos += 1;
            at_count = 2;
        }
        
        self.current.count = at_count;
        
        // Handle special cases like @@`version`
        if new_pos < slen {
            if self.input[new_pos] == b'`' {
                self.pos = new_pos;
                let result = self.parse_tick();
                
                // Store only the backtick content (without @ symbols) like C
                // The backtick content is already parsed correctly by parse_tick
                self.current.token_type = TokenType::Variable;
                return result;
            } else if self.input[new_pos] == CHAR_SINGLE || self.input[new_pos] == CHAR_DOUBLE {
                self.pos = new_pos;
                let result = self.parse_string();
                
                // Store only the string content (without @ symbols) like C
                // The string content is already parsed correctly by parse_string
                self.current.token_type = TokenType::Variable;
                return result;
            }
        }
        
        // Regular variable name
        let var_chars = b" <>:?=@!#~+-*/&|^%(),;'	\n\x0B\x0C\r'`\"";
        let mut end_pos = new_pos;
        
        while end_pos < slen && !var_chars.contains(&self.input[end_pos]) {
            end_pos += 1;
        }
        
        if end_pos == new_pos {
            // Empty variable name (just @ or @@ symbols)
            // Store the @ symbols like C implementation 
            let var_slice = &self.input[self.pos..new_pos]; // Include @ symbols
            self.current.assign(TYPE_VARIABLE, self.pos, new_pos - self.pos, var_slice);
            new_pos
        } else {
            // Non-empty variable - store the @ symbols + name like C
            let var_slice = &self.input[self.pos..end_pos]; // Include @ symbols
            self.current.assign(TYPE_VARIABLE, self.pos, end_pos - self.pos, var_slice);
            end_pos
        }
    }
    
    fn parse_money(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        if pos + 1 == slen {
            self.current.assign_char(TYPE_BAREWORD, pos, b'$');
            return slen;
        }
        
        let next_char = self.input[pos + 1];
        
        // Check for $1,000.00 format
        let money_chars = b"0123456789.,";
        let mut end_pos = pos + 1;
        
        while end_pos < slen && money_chars.contains(&self.input[end_pos]) {
            end_pos += 1;
        }
        
        if end_pos > pos + 1 {
            // Check for special case: $. should be parsed as word
            if end_pos == pos + 2 && self.input[pos + 1] == b'.' {
                return self.parse_word();
            }
            // Found numeric content
            let money_slice = &self.input[pos..end_pos];
            self.current.assign(TYPE_NUMBER, pos, end_pos - pos, money_slice);
            return end_pos;
        }
        
        // Check for PostgreSQL $$ strings
        if next_char == b'$' {
            return self.parse_dollar_string();
        }
        
        // Check for PostgreSQL $tag$ strings
        let tag_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut tag_end = pos + 1;
        
        while tag_end < slen && tag_chars.contains(&self.input[tag_end]) {
            tag_end += 1;
        }
        
        if tag_end == pos + 1 {
            // Just $ followed by non-alphanumeric
            self.current.assign_char(TYPE_BAREWORD, pos, b'$');
            pos + 1
        } else if tag_end < slen && self.input[tag_end] == b'$' {
            // Found $tag$ pattern
            self.parse_tagged_dollar_string(tag_end)
        } else {
            // $ followed by letters but no closing $
            self.current.assign_char(TYPE_BAREWORD, pos, b'$');
            pos + 1
        }
    }
    
    fn parse_number(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        let mut end_pos = pos;
        let mut have_e = false;
        let mut have_exp = false;
        
        // Handle special prefixes 0x, 0X, 0b, 0B
        if end_pos < slen && self.input[end_pos] == b'0' && end_pos + 1 < slen {
            match self.input[end_pos + 1] {
                b'X' | b'x' => {
                    end_pos += 2;
                    while end_pos < slen {
                        match self.input[end_pos] {
                            b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => end_pos += 1,
                            _ => break,
                        }
                    }
                    
                    if end_pos == pos + 2 {
                        // No hex digits after 0x
                        let token = &self.input[pos..pos + 2];
                        self.current.assign(TYPE_BAREWORD, pos, 2, token);
                        return pos + 2;
                    } else {
                        let token = &self.input[pos..end_pos];
                        self.current.assign(TYPE_NUMBER, pos, end_pos - pos, token);
                        return end_pos;
                    }
                }
                b'B' | b'b' => {
                    end_pos += 2;
                    while end_pos < slen && (self.input[end_pos] == b'0' || self.input[end_pos] == b'1') {
                        end_pos += 1;
                    }
                    
                    if end_pos == pos + 2 {
                        // No binary digits after 0b
                        let token = &self.input[pos..pos + 2];
                        self.current.assign(TYPE_BAREWORD, pos, 2, token);
                        return pos + 2;
                    } else {
                        let token = &self.input[pos..end_pos];
                        self.current.assign(TYPE_NUMBER, pos, end_pos - pos, token);
                        return end_pos;
                    }
                }
                _ => {} // Continue with normal number parsing
            }
        }
        
        let start_pos = end_pos;
        
        // Parse integer part
        while end_pos < slen && self.input[end_pos].is_ascii_digit() {
            end_pos += 1;
        }
        
        // Parse decimal part
        if end_pos < slen && self.input[end_pos] == b'.' {
            end_pos += 1;
            while end_pos < slen && self.input[end_pos].is_ascii_digit() {
                end_pos += 1;
            }
            
            if end_pos - start_pos == 1 {
                // Only read '.', this is a dot token
                self.current.assign_char(TYPE_DOT, start_pos, b'.');
                return end_pos;
            }
        }
        
        // Parse exponent
        if end_pos < slen && (self.input[end_pos] == b'E' || self.input[end_pos] == b'e') {
            have_e = true;
            end_pos += 1;
            
            if end_pos < slen && (self.input[end_pos] == b'+' || self.input[end_pos] == b'-') {
                end_pos += 1;
            }
            
            while end_pos < slen && self.input[end_pos].is_ascii_digit() {
                have_exp = true;
                end_pos += 1;
            }
        }
        
        // Oracle float/double suffix
        if end_pos < slen {
            match self.input[end_pos] {
                b'd' | b'D' | b'f' | b'F' => {
                    if end_pos + 1 == slen {
                        end_pos += 1;
                    } else if self.is_white_char(self.input[end_pos + 1]) || self.input[end_pos + 1] == b';' {
                        end_pos += 1;
                    } else if end_pos + 1 < slen && (self.input[end_pos + 1] == b'u' || self.input[end_pos + 1] == b'U') {
                        // Handle "1fUNION" -> "1f" "UNION"
                        end_pos += 1;
                    }
                }
                _ => {}
            }
        }
        
        // Check for invalid exponential format
        if have_e && !have_exp {
            let token = &self.input[start_pos..end_pos];
            self.current.assign(TYPE_BAREWORD, start_pos, end_pos - start_pos, token);
        } else {
            let token = &self.input[start_pos..end_pos];
            self.current.assign(TYPE_NUMBER, start_pos, end_pos - start_pos, token);
        }
        
        end_pos
    }
    
    // Helper functions
    
    fn is_white_char(&self, ch: u8) -> bool {
        use crate::sqli::sqli_data::{get_char_type, CharType};
        matches!(get_char_type(ch), CharType::White)
    }
    
    fn memchr(&self, needle: u8, haystack: &[u8]) -> Option<usize> {
        haystack.iter().position(|&x| x == needle)
    }
    
    fn is_backslash_escaped(&self, pos: usize) -> bool {
        let mut backslash_count = 0;
        let mut current_pos = pos;
        
        // Count consecutive backslashes backwards from pos (including pos itself)
        while current_pos < self.input.len() && self.input[current_pos] == b'\\' {
            backslash_count += 1;
            if current_pos == 0 {
                break;
            }
            current_pos -= 1;
        }
        
        // If odd number of backslashes, the character after them is escaped
        backslash_count & 1 == 1
    }
    
    fn is_double_delim_escaped(&self, pos: usize) -> bool {
        pos + 1 < self.input.len() && self.input[pos] == self.input[pos + 1]
    }
    
    fn find_qstring_end(&self, start: usize, end_delim: u8) -> Option<usize> {
        let mut pos = start;
        
        while pos + 1 < self.input.len() {
            if self.input[pos] == end_delim && self.input[pos + 1] == b'\'' {
                return Some(pos);
            }
            pos += 1;
        }
        
        None
    }
    
    fn parse_dollar_string(&mut self) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        
        // $$ string $$
        let content_start = pos + 2;
        
        // Find ending $$
        let mut end_pos = content_start;
        while end_pos + 1 < slen {
            if self.input[end_pos] == b'$' && self.input[end_pos + 1] == b'$' {
                let content = &self.input[content_start..end_pos];
                self.current.assign(TYPE_STRING, content_start, end_pos - content_start, content);
                self.current.str_open = b'$';
                self.current.str_close = b'$';
                return end_pos + 2;
            }
            end_pos += 1;
        }
        
        // No closing $$ found
        let content = &self.input[content_start..];
        self.current.assign(TYPE_STRING, content_start, slen - content_start, content);
        self.current.str_open = b'$';
        self.current.str_close = CHAR_NULL;
        slen
    }
    
    fn parse_tagged_dollar_string(&mut self, tag_end: usize) -> usize {
        let pos = self.pos;
        let slen = self.input.len();
        let tag = &self.input[pos..=tag_end];
        let content_start = tag_end + 1;
        
        // Find matching end tag
        let mut search_pos = content_start;
        while search_pos + tag.len() <= slen {
            if &self.input[search_pos..search_pos + tag.len()] == tag {
                let content = &self.input[content_start..search_pos];
                self.current.assign(TYPE_STRING, content_start, search_pos - content_start, content);
                self.current.str_open = b'$';
                self.current.str_close = b'$';
                return search_pos + tag.len();
            }
            search_pos += 1;
        }
        
        // No matching end tag
        let content = &self.input[content_start..];
        self.current.assign(TYPE_STRING, content_start, slen - content_start, content);
        self.current.str_open = b'$';
        self.current.str_close = CHAR_NULL;
        slen
    }
}