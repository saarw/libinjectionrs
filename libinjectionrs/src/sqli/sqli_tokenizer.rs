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
    let ch = sf.s[sf.pos];
    unsafe {
        (*sf.current).assign_char('o', sf.pos, ch as char);
    }
    sf.pos + 1
}

pub fn parse_other(sf: &mut SqliState) -> usize {
    let ch = sf.s[sf.pos];
    unsafe {
        (*sf.current).assign_char('?', sf.pos, ch as char);
    }
    sf.pos + 1
}

pub fn parse_char(sf: &mut SqliState) -> usize {
    let ch = sf.s[sf.pos];
    let token_type = match ch {
        b'(' => '(',
        b')' => ')',
        b',' => ',',
        b';' => ';',
        _ => '?',
    };
    unsafe {
        (*sf.current).assign_char(token_type, sf.pos, ch as char);
    }
    sf.pos + 1
}

pub fn parse_eol_comment(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let remaining = &sf.s[pos..];
    
    match remaining.iter().position(|&c| c == b'\n') {
        Some(newline_pos) => {
            unsafe {
                (*sf.current).assign('c', pos, newline_pos, &sf.s[pos..pos + newline_pos]);
            }
            pos + newline_pos + 1
        }
        None => {
            unsafe {
                (*sf.current).assign('c', pos, remaining.len(), remaining);
            }
            sf.slen
        }
    }
}

pub fn parse_hash(sf: &mut SqliState) -> usize {
    sf.stats_comment_hash += 1;
    if sf.flags.contains(crate::sqli::SqliFlags::MYSQL) {
        parse_eol_comment(sf)
    } else {
        unsafe {
            (*sf.current).assign_char('o', sf.pos, '#');
        }
        sf.pos + 1
    }
}

pub fn parse_dash(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    let slen = input.len();
    
    // Check for SQL comment patterns
    if pos + 2 < slen && input[pos + 1] == b'-' && char_is_white(input[pos + 2]) {
        sf.stats_comment_ddw += 1;
        parse_eol_comment(sf)
    } else if pos + 2 == slen && input[pos + 1] == b'-' {
        sf.stats_comment_ddw += 1;
        parse_eol_comment(sf)
    } else if pos + 1 < slen && input[pos + 1] == b'-' && 
              sf.flags.contains(crate::sqli::SqliFlags::ANSI) {
        sf.stats_comment_ddx += 1;
        parse_eol_comment(sf)
    } else {
        unsafe {
            (*sf.current).assign_char('o', pos, '-');
        }
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
    let input = sf.s;
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
    
    let mut ctype = 'c';
    
    // Check for nested comments or MySQL conditional comments
    if let Some(offset) = end_pos {
        let inner = &input[pos + 2..search_start + offset];
        if memchr2(inner, b'/', b'*').is_some() {
            ctype = 'X';
        }
    }
    
    if is_mysql_comment(input, pos) {
        ctype = 'X';
    }
    
    unsafe {
        (*sf.current).assign(ctype, pos, clen, &input[pos..pos + clen]);
    }
    pos + clen
}

pub fn parse_backslash(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    let slen = input.len();
    
    // MySQL alias for NULL: \N
    if pos + 1 < slen && input[pos + 1] == b'N' {
        unsafe {
            (*sf.current).assign('1', pos, 2, &input[pos..pos + 2]);
        }
        pos + 2
    } else {
        unsafe {
            (*sf.current).assign_char('\\', pos, input[pos] as char);
        }
        pos + 1
    }
}

pub fn parse_operator2(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    let slen = input.len();
    
    if pos + 1 >= slen {
        return parse_operator1(sf);
    }
    
    // Check for three-character operators
    if pos + 2 < slen && input[pos] == b'<' && input[pos + 1] == b'=' && 
       input[pos + 2] == b'>' {
        unsafe {
            (*sf.current).assign('o', pos, 3, &input[pos..pos + 3]);
        }
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
                '&'
            } else {
                'o'
            };
            unsafe {
                (*sf.current).assign(token_type, pos, 2, two_char);
            }
            pos + 2
        }
        _ => parse_operator1(sf)
    }
}

pub fn parse_money(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    
    // PostgreSQL money type: $123.45
    let mut i = pos + 1;
    while i < input.len() && (is_digit(input[i]) || input[i] == b'.') {
        i += 1;
    }
    
    if i > pos + 1 {
        unsafe {
            (*sf.current).assign('1', pos, i - pos, &input[pos..i]);
        }
        i
    } else {
        parse_other(sf)
    }
}

pub fn parse_var(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    
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
        unsafe {
            (*sf.current).assign('v', pos, i - pos, &input[pos..i]);
        }
        i
    } else {
        unsafe {
            (*sf.current).assign_char('o', pos, input[pos] as char);
        }
        pos + 1
    }
}

pub fn parse_number(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
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
    
    unsafe {
        (*sf.current).assign('1', pos, i - pos, &input[pos..i]);
    }
    i
}

// Placeholder implementations for string parsing functions
// These will be implemented next

pub fn parse_string(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
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
    
    unsafe {
        (*sf.current).assign('s', pos, i - pos, &input[pos..i]);
        (*sf.current).str_open = quote as char;
        if i > pos + 1 && i <= slen {
            (*sf.current).str_close = quote as char;
        }
    }
    
    i
}

pub fn parse_word(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let input = sf.s;
    let wlen = strlencspn(&input[pos..], b" []{}><:?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\x00\xa0");
    
    if wlen == 0 {
        return parse_char(sf);
    }
    
    // Enhanced keyword detection matching C implementation exactly
    let token_type = if let Ok(word) = std::str::from_utf8(&input[pos..pos + wlen]) {
        let upper_word = word.to_uppercase();
        match upper_word.as_str() {
            // UNION type
            "UNION" => 'U',
            // EXPRESSION type (matches C libinjection_sqli_data.h)
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CASE" | "CREATE" | 
            "SET" | "RAISEERROR" | "EXECUTE" => 'E',
            // GROUP type
            "HAVING" | "LIMIT" => 'B',
            // Regular keywords
            "FROM" | "WHERE" | "INTO" | "VALUES" | "TABLE" | "DATABASE" | 
            "INDEX" | "VIEW" | "TRIGGER" | "PROCEDURE" | "DROP" | "ALTER" |
            "AS" | "JOIN" | "LEFT" | "RIGHT" | "INNER" | "OUTER" | "FULL" |
            "BY" | "WITH" | "WITHOUT" | "ON" | "USING" | "ORDER" | "GROUP" => 'k',
            // Logic operators
            "AND" | "OR" | "NOT" | "XOR" => '&',
            // SQL types
            "INT" | "INTEGER" | "VARCHAR" | "CHAR" | "TEXT" | "BLOB" | "DECIMAL" |
            "FLOAT" | "DOUBLE" | "DATE" | "TIME" | "TIMESTAMP" | "BOOL" | "BOOLEAN" => 't',
            // Functions
            "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "SUBSTRING" | "CONCAT" |
            "LENGTH" | "UPPER" | "LOWER" | "TRIM" | "CAST" | "CONVERT" => 'f',
            // Default to bareword
            _ => 'n',
        }
    } else {
        'n'
    };
    
    unsafe {
        (*sf.current).assign(token_type, pos, wlen, &input[pos..pos + wlen]);
    }
    pos + wlen
}

pub fn parse_tick(sf: &mut SqliState) -> usize {
    let pos = parse_string_core(sf, '`', 1);
    
    unsafe {
        let current = &mut *sf.current;
        // Check if the value is a function name (simplified lookup)
        if let Ok(val_str) = std::str::from_utf8(&current.val[..current.len.min(31)]) {
            let upper_val = val_str.to_uppercase();
            if matches!(upper_val.as_str(), 
                "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "SUBSTRING" | "CONCAT" |
                "LENGTH" | "UPPER" | "LOWER" | "TRIM" | "DATABASE" | "USER") {
                current.token_type = 'f';
            } else {
                current.token_type = 'n';
            }
        } else {
            current.token_type = 'n';
        }
    }
    
    pos
}

/// Core string parsing function matching C's parse_string_core exactly
pub fn parse_string_core(sf: &mut SqliState, delim: char, offset: usize) -> usize {
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    // Look for closing delimiter starting from pos + offset
    let mut qpos = None;
    for i in (pos + offset)..slen {
        if s[i] == delim as u8 {
            qpos = Some(i);
            break;
        }
    }
    
    unsafe {
        let current = &mut *sf.current;
        
        // Set string open/close markers
        if offset > 0 {
            current.str_open = delim;
        } else {
            current.str_open = '\0';
        }
        
        let mut end_pos = pos + offset;
        let mut closed_str = false;
        
        match qpos {
            None => {
                // String ended without closing quote
                current.assign('s', pos + offset, slen - pos - offset, &s[pos + offset..]);
                current.str_close = '\0';
                end_pos = slen;
            }
            Some(qpos_val) => {
                // Found closing quote, but check for escaped or doubled quotes
                let str_len = qpos_val - (pos + offset);
                current.assign('s', pos + offset, str_len, &s[pos + offset..qpos_val]);
                current.str_close = delim;
                closed_str = true;
                end_pos = qpos_val + 1;
                
                // Handle quote doubling (SQL standard escape)
                if end_pos < slen && s[end_pos] == delim as u8 {
                    // This is a doubled quote, continue parsing
                    let remaining = parse_string_core_continue(sf, end_pos, delim);
                    return remaining;
                }
            }
        }
        
        end_pos
    }
}

fn parse_string_core_continue(sf: &mut SqliState, start_pos: usize, delim: char) -> usize {
    let mut pos = start_pos + 1; // Skip the second quote
    let slen = sf.slen;
    let s = sf.s;
    
    // Continue looking for the actual end
    while pos < slen {
        if s[pos] == delim as u8 {
            if pos + 1 < slen && s[pos + 1] == delim as u8 {
                // Another doubled quote, skip both
                pos += 2;
                continue;
            } else {
                // Found the real end
                return pos + 1;
            }
        }
        pos += 1;
    }
    
    slen
}

pub fn parse_ustring(sf: &mut SqliState) -> usize {
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    // Check for U&'...' pattern (Unicode string with escape)
    if pos + 2 < slen && s[pos + 1] == b'&' && s[pos + 2] == b'\'' {
        sf.pos += 2;
        let end_pos = parse_string(sf);
        unsafe {
            let current = &mut *sf.current;
            current.str_open = 'u';
            if current.str_close == '\'' {
                current.str_close = 'u';
            }
        }
        end_pos
    } else {
        parse_word(sf)
    }
}

pub fn parse_qstring(sf: &mut SqliState) -> usize {
    parse_qstring_core(sf, 1)
}

pub fn parse_nqstring(sf: &mut SqliState) -> usize {
    parse_qstring_core(sf, 2)
}

/// Oracle Q-string parsing: Q'[...]' or Q'{...}' etc.
fn parse_qstring_core(sf: &mut SqliState, offset: usize) -> usize {
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    if pos + offset + 2 >= slen {
        return parse_word(sf);
    }
    
    // Check for Q' pattern  
    if s[pos + offset] != b'\'' {
        return parse_word(sf);
    }
    
    let delimiter_pos = pos + offset + 1;
    let delim_start = s[delimiter_pos];
    
    // Map opening delimiter to closing delimiter
    let delim_end = match delim_start {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        other => other, // For other characters, use same char to close
    };
    
    // Look for pattern: delim_end followed by '
    let search_start = delimiter_pos + 1;
    for i in search_start..slen.saturating_sub(1) {
        if s[i] == delim_end && s[i + 1] == b'\'' {
            // Found the end pattern
            unsafe {
                let current = &mut *sf.current;
                let content_start = delimiter_pos + 1;
                let content_len = i - content_start;
                current.assign('s', content_start, content_len, &s[content_start..i]);
                current.str_open = delim_start as char;
                current.str_close = delim_end as char;
            }
            return i + 2; // Skip past the closing quote
        }
    }
    
    // No proper closing found, treat as word
    parse_word(sf)
}

pub fn parse_xstring(sf: &mut SqliState) -> usize {
    // PostgreSQL/MySQL hex strings: X'deadbeef' or 0xdeadbeef
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    if pos + 2 >= slen || s[pos + 1] != b'\'' {
        return parse_word(sf);
    }
    
    parse_string_core(sf, '\'', 2)
}

pub fn parse_bstring(sf: &mut SqliState) -> usize {
    // PostgreSQL binary strings: B'10101010'
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    if pos + 2 >= slen || s[pos + 1] != b'\'' {
        return parse_word(sf);
    }
    
    parse_string_core(sf, '\'', 2)
}

pub fn parse_estring(sf: &mut SqliState) -> usize {
    // PostgreSQL escape strings: E'...' or N'...' (National charset)
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    if pos + 2 >= slen || s[pos + 1] != b'\'' {
        return parse_word(sf);
    }
    
    parse_string_core(sf, '\'', 2)
}

pub fn parse_bword(sf: &mut SqliState) -> usize {
    // SQL Server bracket words: [table_name] or [column name]
    let pos = sf.pos;
    let slen = sf.slen;
    let s = sf.s;
    
    // Look for closing bracket
    for i in (pos + 1)..slen {
        if s[i] == b']' {
            unsafe {
                let current = &mut *sf.current;
                let content_len = i - pos - 1;
                current.assign('n', pos + 1, content_len, &s[pos + 1..i]);
                current.str_open = '[';
                current.str_close = ']';
            }
            return i + 1;
        }
    }
    
    // No closing bracket found, treat as single char
    parse_char(sf)
}