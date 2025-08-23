/// SQL tokenizer implementation
/// Direct transliteration from libinjection_sqli.c

use crate::sqli::{SqliState, Token};

// Constants from C
const CHAR_NULL: u8 = b'\0';
const CHAR_SINGLE: u8 = b'\'';
const CHAR_DOUBLE: u8 = b'"';
const CHAR_TICK: u8 = b'`';

// Token type constants matching C enum values
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

/// Maximum token value size
const TOKEN_SIZE: usize = 32;

/// Check if character is whitespace (SQL definition)
#[inline]
pub fn char_is_white(ch: u8) -> bool {
    matches!(ch, b' ' | b'\t' | b'\n' | 0x0b | b'\x0c' | b'\r' | 0xa0 | 0x00)
}

/// Check if character is a digit
#[inline]
pub fn is_digit(ch: u8) -> bool {
    ch >= b'0' && ch <= b'9'
}

/// Case-insensitive comparison of uppercase string with arbitrary memory
fn cstrcasecmp(a: &[u8], b: &[u8]) -> i32 {
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

/// Find two-character sequence in memory
fn memchr2(haystack: &[u8], needle1: u8, needle2: u8) -> Option<usize> {
    for i in 0..haystack.len().saturating_sub(1) {
        if haystack[i] == needle1 && haystack[i + 1] == needle2 {
            return Some(i);
        }
    }
    None
}

/// Count characters in string that are NOT in the charset
fn strlencspn(input: &[u8], charset: &[u8]) -> usize {
    for (i, &ch) in input.iter().enumerate() {
        if charset.contains(&ch) {
            return i;
        }
    }
    input.len()
}

/// Check if a character at position is backslash escaped
fn is_backslash_escaped(input: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return false;
    }
    
    let mut count = 0;
    let mut i = pos - 1;
    
    loop {
        if input[i] != b'\\' {
            break;
        }
        count += 1;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    
    count % 2 == 1
}

// Parsing functions implementation

pub fn parse_white(sf: &mut SqliState) -> usize {
    sf.pos + 1
}

pub fn parse_operator1(sf: &mut SqliState) -> usize {
    let ch = sf.input[sf.pos];
    sf.current = Token::new_char(TYPE_OPERATOR, sf.pos, ch);
    sf.pos + 1
}

pub fn parse_other(sf: &mut SqliState) -> usize {
    let ch = sf.input[sf.pos];
    sf.current = Token::new_char(TYPE_UNKNOWN, sf.pos, ch);
    sf.pos + 1
}

pub fn parse_char(sf: &mut SqliState) -> usize {
    let ch = sf.input[sf.pos];
    sf.current = Token::new_char(ch, sf.pos, ch);
    sf.pos + 1
}

pub fn parse_eol_comment(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let remaining = &sf.input[pos..];
    
    match remaining.iter().position(|&c| c == b'\n') {
        Some(newline_pos) => {
            sf.current = Token::new(TYPE_COMMENT, pos, &sf.input[pos..pos + newline_pos]);
            pos + newline_pos + 1
        }
        None => {
            sf.current = Token::new(TYPE_COMMENT, pos, remaining);
            sf.input.len()
        }
    }
}

pub fn parse_hash(sf: &mut SqliState) -> usize {
    sf.stats_comment_hash += 1;
    if sf.flags.contains(crate::sqli::SqliFlags::MYSQL) {
        sf.stats_comment_hash += 1;
        parse_eol_comment(sf)
    } else {
        sf.current = Token::new_char(TYPE_OPERATOR, sf.pos, b'#');
        sf.pos + 1
    }
}

pub fn parse_dash(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let slen = input.len();
    
    // Check for SQL comment patterns
    if pos + 2 < slen && input[pos + 1] == b'-' && char_is_white(input[pos + 2]) {
        parse_eol_comment(sf)
    } else if pos + 2 == slen && input[pos + 1] == b'-' {
        parse_eol_comment(sf)
    } else if pos + 1 < slen && input[pos + 1] == b'-' && 
              sf.flags.contains(crate::sqli::SqliFlags::ANSI) {
        sf.stats_comment_ddx += 1;
        parse_eol_comment(sf)
    } else {
        sf.current = Token::new_char(TYPE_OPERATOR, pos, b'-');
        pos + 1
    }
}

fn is_mysql_comment(input: &[u8], pos: usize) -> bool {
    // Check for MySQL comment form: /*! 
    if pos + 2 >= input.len() {
        return false;
    }
    
    if input[pos + 2] != b'!' {
        return false;
    }
    
    true
}

pub fn parse_slash(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let slen = input.len();
    
    if pos + 1 == slen || input[pos + 1] != b'*' {
        return parse_operator1(sf);
    }
    
    // Look for closing */
    let search_start = pos + 2;
    let search_area = &input[search_start..];
    
    let end_pos = memchr2(search_area, b'*', b'/');
    
    let clen = match end_pos {
        Some(offset) => offset + search_start - pos + 2,
        None => slen - pos,
    };
    
    let mut ctype = TYPE_COMMENT;
    
    // Check for nested comments or MySQL conditional comments
    if let Some(offset) = end_pos {
        let inner = &input[pos + 2..search_start + offset];
        if memchr2(inner, b'/', b'*').is_some() {
            ctype = TYPE_EVIL;
        }
    }
    
    if is_mysql_comment(input, pos) {
        ctype = TYPE_EVIL;
    }
    
    sf.current = Token::new(ctype, pos, &input[pos..pos + clen]);
    pos + clen
}

pub fn parse_backslash(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let slen = input.len();
    
    // MySQL alias for NULL: \N
    if pos + 1 < slen && input[pos + 1] == b'N' {
        sf.current = Token::new(TYPE_NUMBER, pos, &input[pos..pos + 2]);
        pos + 2
    } else {
        sf.current = Token::new_char(TYPE_BACKSLASH, pos, input[pos]);
        pos + 1
    }
}

pub fn parse_operator2(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let slen = input.len();
    
    if pos + 1 >= slen {
        return parse_operator1(sf);
    }
    
    // Check for three-character operators
    if pos + 2 < slen && input[pos] == b'<' && input[pos + 1] == b'=' && 
       input[pos + 2] == b'>' {
        sf.current = Token::new(TYPE_OPERATOR, pos, &input[pos..pos + 3]);
        return pos + 3;
    }
    
    // Check for two-character operators
    let two_char = &input[pos..pos + 2];
    match two_char {
        b"!=" | b"!<" | b"!>" | b"%=" | b"&&" | b"&=" | b"*=" | 
        b"+=" | b"-=" | b"/=" | b"::" | b":=" | b"<<" | b"<=" | 
        b"<>" | b"<@" | b">=" | b">>" | b"??" | b"@>" | b"^=" | 
        b"|/" | b"|=" | b"||" | b"~*" => {
            let token_type = if two_char == b"&&" || two_char == b"||" {
                TYPE_LOGIC_OPERATOR
            } else {
                TYPE_OPERATOR
            };
            sf.current = Token::new(token_type, pos, two_char);
            pos + 2
        }
        _ => parse_operator1(sf)
    }
}

pub fn parse_money(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    
    // PostgreSQL money type: $123.45
    let mut i = pos + 1;
    while i < input.len() && (is_digit(input[i]) || input[i] == b'.') {
        i += 1;
    }
    
    if i > pos + 1 {
        sf.current = Token::new(TYPE_NUMBER, pos, &input[pos..i]);
        i
    } else {
        parse_other(sf)
    }
}

pub fn parse_var(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    
    // SQL variables: @var, @@var
    let mut i = pos + 1;
    
    // Check for @@
    if i < input.len() && input[i] == b'@' {
        i += 1;
    }
    
    // Parse variable name
    while i < input.len() {
        let ch = input[i];
        if ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'$' {
            i += 1;
        } else {
            break;
        }
    }
    
    if i > pos + 1 {
        sf.current = Token::new(TYPE_VARIABLE, pos, &input[pos..i]);
        i
    } else {
        sf.current = Token::new_char(TYPE_OPERATOR, pos, input[pos]);
        pos + 1
    }
}

pub fn parse_number(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let mut i = pos;
    
    // Parse integer part
    while i < input.len() && is_digit(input[i]) {
        i += 1;
    }
    
    // Check for decimal point
    if i < input.len() && input[i] == b'.' {
        i += 1;
        while i < input.len() && is_digit(input[i]) {
            i += 1;
        }
    }
    
    // Check for exponent
    if i < input.len() && (input[i] == b'e' || input[i] == b'E') {
        i += 1;
        if i < input.len() && (input[i] == b'+' || input[i] == b'-') {
            i += 1;
        }
        while i < input.len() && is_digit(input[i]) {
            i += 1;
        }
    }
    
    sf.current = Token::new(TYPE_NUMBER, pos, &input[pos..i]);
    i
}

// Placeholder implementations for string parsing functions
// These will be implemented next

pub fn parse_string(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let slen = input.len();
    let quote = input[pos];
    let mut i = pos + 1;
    
    // Find closing quote, handling escapes
    while i < slen {
        let ch = input[i];
        
        if ch == quote {
            // Check for doubled quotes (SQL standard escape)
            if i + 1 < slen && input[i + 1] == quote {
                i += 2; // Skip doubled quote
                continue;
            } else {
                // Found closing quote
                i += 1;
                break;
            }
        } else if ch == b'\\' {
            // Check for backslash escape
            if i + 1 < slen {
                i += 2; // Skip escaped character
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    
    sf.current = Token::new(TYPE_STRING, pos, &input[pos..i]);
    sf.current.str_open = Some(quote);
    if i > pos + 1 && i <= slen {
        sf.current.str_close = Some(quote);
    }
    
    i
}

pub fn parse_word(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.input;
    let wlen = strlencspn(&input[pos..], b" []{}><:?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\x00\xa0");
    
    if wlen == 0 {
        return parse_char(sf);
    }
    
    // Enhanced keyword detection matching C implementation
    let token_type = if let Ok(word) = std::str::from_utf8(&input[pos..pos + wlen]) {
        let upper_word = word.to_uppercase();
        match upper_word.as_str() {
            "UNION" => TYPE_UNION,
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER" |
            "FROM" | "WHERE" | "INTO" | "VALUES" | "SET" | "TABLE" | "DATABASE" |
            "INDEX" | "VIEW" | "TRIGGER" | "PROCEDURE" | "FUNCTION" => TYPE_KEYWORD,
            "AND" | "OR" | "NOT" | "XOR" => TYPE_LOGIC_OPERATOR,
            "INT" | "INTEGER" | "VARCHAR" | "CHAR" | "TEXT" | "BLOB" | "DECIMAL" |
            "FLOAT" | "DOUBLE" | "DATE" | "TIME" | "TIMESTAMP" => TYPE_SQLTYPE,
            "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "SUBSTRING" | "CONCAT" |
            "LENGTH" | "UPPER" | "LOWER" | "TRIM" => TYPE_FUNCTION,
            _ => TYPE_BAREWORD,
        }
    } else {
        TYPE_BAREWORD
    };
    
    sf.current = Token::new(token_type, pos, &input[pos..pos + wlen]);
    pos + wlen
}

pub fn parse_tick(sf: &mut SqliState) -> usize {
    // TODO: Implement backtick parsing
    parse_char(sf)
}

pub fn parse_ustring(sf: &mut SqliState) -> usize {
    // TODO: Implement Unicode string parsing
    parse_word(sf)
}

pub fn parse_qstring(sf: &mut SqliState) -> usize {
    // TODO: Implement Q-string parsing
    parse_word(sf)
}

pub fn parse_nqstring(sf: &mut SqliState) -> usize {
    // TODO: Implement N-string parsing  
    parse_word(sf)
}

pub fn parse_xstring(sf: &mut SqliState) -> usize {
    // TODO: Implement hex string parsing
    parse_word(sf)
}

pub fn parse_bstring(sf: &mut SqliState) -> usize {
    // TODO: Implement binary string parsing
    parse_word(sf)
}

pub fn parse_estring(sf: &mut SqliState) -> usize {
    // TODO: Implement escape string parsing
    parse_word(sf)
}

pub fn parse_bword(sf: &mut SqliState) -> usize {
    // TODO: Implement bracket word parsing
    parse_char(sf)
}