use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Html5Flags {
    DataState = 0,
    ValueNoQuote = 1,
    ValueSingleQuote = 2,
    ValueDoubleQuote = 3,
    ValueBackQuote = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    DataText,
    TagNameOpen,
    TagNameClose, 
    TagNameSelfclose,
    TagData,
    TagClose,
    AttrName,
    AttrValue,
    TagComment,
    Doctype,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TokenType::DataText => "DATA_TEXT",
            TokenType::TagNameOpen => "TAG_NAME_OPEN", 
            TokenType::TagNameClose => "TAG_NAME_CLOSE",
            TokenType::TagNameSelfclose => "TAG_NAME_SELFCLOSE",
            TokenType::TagData => "TAG_DATA",
            TokenType::TagClose => "TAG_CLOSE",
            TokenType::AttrName => "ATTR_NAME",
            TokenType::AttrValue => "ATTR_VALUE",
            TokenType::TagComment => "TAG_COMMENT",
            TokenType::Doctype => "DOCTYPE",
        };
        write!(f, "{}", name)
    }
}

pub struct Html5State<'a> {
    s: &'a [u8],
    len: usize,
    pos: usize,
    pub token_type: TokenType,
    pub token_start: &'a [u8],
    pub token_len: usize,
    state_fn: fn(&mut Html5State<'a>) -> bool,
    is_close: bool,
}

impl<'a> Html5State<'a> {
    pub fn new(input: &'a [u8], flags: Html5Flags) -> Self {
        let state_fn = match flags {
            Html5Flags::DataState => Self::state_data,
            Html5Flags::ValueNoQuote => Self::state_before_attribute_name,
            Html5Flags::ValueSingleQuote => Self::state_attribute_value_single_quote,
            Html5Flags::ValueDoubleQuote => Self::state_attribute_value_double_quote,
            Html5Flags::ValueBackQuote => Self::state_attribute_value_back_quote,
        };

        Html5State {
            s: input,
            len: input.len(),
            pos: 0,
            token_type: TokenType::DataText,
            token_start: input,
            token_len: 0,
            state_fn,
            is_close: false,
        }
    }

    pub fn next(&mut self) -> bool {
        (self.state_fn)(self)
    }
    
    pub fn position(&self) -> usize {
        self.pos
    }
    
    #[cfg(test)]
    pub fn debug_is_close(&self) -> bool {
        self.is_close
    }
    
    #[cfg(test)]
    pub fn debug_pos(&self) -> usize {
        self.pos
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.len
    }

    fn current_char(&self) -> Option<u8> {
        if self.pos < self.len {
            Some(self.s[self.pos])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<u8> {
        if self.pos < self.len {
            let ch = self.s[self.pos];
            self.pos += 1;
            Some(ch)
        } else {
            None
        }
    }

    #[allow(dead_code)] // Follows C implementation - may be used in future HTML5 parsing features
    fn peek(&self, offset: usize) -> Option<u8> {
        let pos = self.pos + offset;
        if pos < self.len {
            Some(self.s[pos])
        } else {
            None
        }
    }

    fn set_token(&mut self, token_type: TokenType, start_pos: usize, len: usize) {
        self.token_type = token_type;
        self.token_start = &self.s[start_pos..];
        self.token_len = len;
    }

    #[allow(dead_code)] // Follows C implementation - may be used in future HTML5 parsing features
    fn skip_whitespace(&mut self) -> Option<u8> {
        while let Some(ch) = self.current_char() {
            if Self::is_whitespace(ch) {
                self.advance();
            } else {
                return Some(ch);
            }
        }
        None
    }
    
    // Match C h5_skip_white exactly: includes 0x00 for IE compatibility
    // CRITICAL: C uses signed char, so any byte >= 128 becomes negative and is returned as-is
    fn h5_skip_white(&mut self) -> Option<i8> {
        while self.pos < self.len {
            let ch_unsigned = self.s[self.pos];
            let ch_signed = ch_unsigned as i8;  // Convert to signed like C does: char ch = hs->s[hs->pos]
            
            match ch_signed {
                0x00 | 0x20 | 0x09 | 0x0A => {  // case 0x00, case 0x20, etc.
                    self.pos += 1;
                }
                0x0B | 0x0C | 0x0D => {  // IE only cases
                    self.pos += 1;
                }
                _ => {
                    // default: return ch;
                    // In C, this returns the signed char value
                    // For 0xFF, this returns -1 (CHAR_EOF)
                    return Some(ch_signed);
                }
            }
        }
        Some(-1)  // CHAR_EOF
    }

    fn find_byte(&self, byte: u8, start: usize) -> Option<usize> {
        if start >= self.len {
            return None;
        }
        
        for i in start..self.len {
            if self.s[i] == byte {
                return Some(i);
            }
        }
        None
    }

    fn find_comment_end(&self, start: usize) -> Option<(usize, usize)> {
        if start + 2 >= self.len {
            return None;
        }
        
        let mut pos = start;
        while pos <= self.len - 3 {
            if let Some(dash_pos) = self.find_byte(b'-', pos) {
                if dash_pos + 2 >= self.len {
                    break;
                }
                
                let mut offset = 1;
                // Skip nulls (IE-ism)
                while dash_pos + offset < self.len && self.s[dash_pos + offset] == 0 {
                    offset += 1;
                }
                
                if dash_pos + offset >= self.len {
                    break;
                }
                
                let next_char = self.s[dash_pos + offset];
                if next_char != b'-' && next_char != b'!' {
                    pos = dash_pos + 1;
                    continue;
                }
                
                offset += 1;
                if dash_pos + offset >= self.len {
                    break;
                }
                
                if self.s[dash_pos + offset] == b'>' {
                    return Some((dash_pos, offset + 1));
                }
                
                pos = dash_pos + 1;
            } else {
                break;
            }
        }
        None
    }

    fn find_cdata_end(&self, start: usize) -> Option<usize> {
        if start + 2 >= self.len {
            return None;
        }
        
        for i in start..self.len - 2 {
            if self.s[i] == b']' && self.s[i + 1] == b']' && self.s[i + 2] == b'>' {
                return Some(i);
            }
        }
        None
    }

    fn is_whitespace(ch: u8) -> bool {
        matches!(ch, 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D)
    }
    
    // Match C h5_is_white function exactly: " \t\n\v\f\r"
    fn h5_is_white(ch: u8) -> bool {
        matches!(ch, 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D)
    }

    // Match C alphabetic check exactly: (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
    // CRITICAL: C uses signed char, so bytes >= 128 become negative and fail the comparison
    fn is_alphabetic_c_style(ch: u8) -> bool {
        let ch_signed = ch as i8;  // Convert to signed like C does
        ((ch_signed >= b'a' as i8) && (ch_signed <= b'z' as i8)) ||
        ((ch_signed >= b'A' as i8) && (ch_signed <= b'Z' as i8))
    }

    fn state_eof(&mut self) -> bool {
        false
    }

    fn state_data(&mut self) -> bool {
        let start = self.pos;
        
        if let Some(lt_pos) = self.find_byte(b'<', self.pos) {
            if lt_pos > start {
                self.set_token(TokenType::DataText, start, lt_pos - start);
                self.pos = lt_pos;
                return true;
            } else {
                self.pos = lt_pos + 1;
                self.state_fn = Self::state_tag_open;
                return self.next();
            }
        } else {
            if self.len > start {
                self.set_token(TokenType::DataText, start, self.len - start);
                self.pos = self.len;
                self.state_fn = Self::state_eof;
                return true;
            } else {
                return false;
            }
        }
    }

    fn state_tag_open(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap_or(0) {
            b'!' => {
                self.advance();
                self.state_fn = Self::state_markup_declaration_open;
                self.next()
            }
            b'/' => {
                self.advance();
                self.is_close = true;
                self.state_fn = Self::state_end_tag_open;
                self.next()
            }
            b'?' => {
                self.advance();
                self.state_fn = Self::state_bogus_comment;
                self.next()
            }
            b'%' => {
                // IE <= 9 and Safari < 4.0.3 alternative comment format
                self.advance();
                self.state_fn = Self::state_bogus_comment2;
                self.next()
            }
            ch if Self::is_alphabetic_c_style(ch) => {
                self.state_fn = Self::state_tag_name;
                self.next()
            }
            0 => {
                // IE-ism: NULL characters are ignored
                self.state_fn = Self::state_tag_name;
                self.next()
            }
            _ => {
                // Invalid character after '<', return '<' as DATA_TEXT and continue from current pos
                if self.pos == 0 {
                    self.state_fn = Self::state_data;
                    return self.next();
                }
                self.set_token(TokenType::DataText, self.pos - 1, 1); // The '<' character
                self.state_fn = Self::state_data;
                true
            }
        }
    }

    fn state_tag_name(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            match ch {
                0 => {
                    // Special non-standard case: allow nulls in tag name
                    // Some old browsers apparently allow and ignore them
                    self.advance();
                }
                ch if Self::is_whitespace(ch) => {
                    self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                    self.advance();
                    self.state_fn = Self::state_before_attribute_name;
                    return true;
                }
                b'/' => {
                    self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                    self.advance();
                    self.state_fn = Self::state_self_closing_start_tag;
                    return true;
                }
                b'>' => {
                    self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                    if self.is_close {
                        self.advance();
                        self.is_close = false;
                        self.token_type = TokenType::TagClose;
                        self.state_fn = Self::state_data;
                    } else {
                        // Match C logic exactly: don't advance pos, keep TagNameOpen, next state handles '>'
                        self.token_type = TokenType::TagNameOpen;
                        self.state_fn = Self::state_tag_name_close;
                    }
                    return true;
                }
                _ => {
                    self.advance();
                }
            }
        }

        self.set_token(TokenType::TagNameOpen, start, self.len - start);
        self.state_fn = Self::state_eof;
        true
    }

    fn state_end_tag_open(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap_or(0) {
            b'>' => {
                self.state_fn = Self::state_data;
                self.next()
            }
            ch if Self::is_alphabetic_c_style(ch) => {
                self.state_fn = Self::state_tag_name;
                self.next()
            }
            _ => {
                self.is_close = false;
                self.state_fn = Self::state_bogus_comment;
                self.next()
            }
        }
    }

    fn state_tag_name_close(&mut self) -> bool {
        // Match C implementation exactly: h5_state_tag_name_close (lines 234-248)
        self.is_close = false;                                  // hs->is_close = 0;
        self.set_token(TokenType::TagNameClose, self.pos, 1);   // token_start = hs->s + hs->pos; token_len = 1; token_type = TAG_NAME_CLOSE;
        self.advance();                                         // hs->pos += 1;
        if self.pos < self.len {                                // if (hs->pos < hs->len) {
            self.state_fn = Self::state_data;                   //     hs->state = h5_state_data;
        } else {                                                // } else {
            self.state_fn = Self::state_eof;                    //     hs->state = h5_state_eof;
        }                                                       // }
        
        true                                                    // return 1;
    }

    fn state_emit_tag_close_char(&mut self) -> bool {
        self.is_close = false;  // Match C behavior - reset is_close when emitting TAG_NAME_CLOSE
        self.set_token(TokenType::TagNameClose, self.pos, 1);
        self.advance();
        if self.pos < self.len {
            self.state_fn = Self::state_data;
        } else {
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_self_closing_start_tag(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }
        
        if self.current_char() == Some(b'>') {
            // Create the TAG_NAME_SELFCLOSE token pointing to the '/' character
            // with length 2 to include both '/' and '>'
            assert!(self.pos > 0);
            self.set_token(TokenType::TagNameSelfclose, self.pos - 1, 2);
            self.advance();
            self.state_fn = Self::state_data;
            return true;
        } else {
            self.state_fn = Self::state_before_attribute_name;
            self.next()
        }
    }

    fn state_before_attribute_name(&mut self) -> bool {
        // Manual tail call optimization loop
        loop {
            match self.h5_skip_white() {
                Some(-1) => return false, // CHAR_EOF
                Some(0x2f) => { // CHAR_SLASH (47 as i8)
                    self.advance();
                    // Tail call optimization: if next char is not '>', loop instead of recursing
                    if self.pos < self.len && self.s[self.pos] != b'>' {
                        continue;
                    }
                    return self.state_self_closing_start_tag();
                }
                Some(0x3e) => { // CHAR_GT (62 as i8)
                    self.set_token(TokenType::TagNameClose, self.pos, 1);
                    self.advance();
                    self.state_fn = Self::state_data;
                    return true;
                }
                Some(_) => {
                    self.state_fn = Self::state_attribute_name;
                    return self.next();
                }
                None => return false, // Should not happen with new implementation
            }
        }
    }

    fn state_attribute_name(&mut self) -> bool {
        // Match C implementation exactly line by line
        let start_pos = self.pos;  // Store initial position
        let mut scan_pos = self.pos + 1;  // pos = hs->pos + 1
        
        while scan_pos < self.len {  // while (pos < hs->len)
            let ch = self.s[scan_pos];  // ch = hs->s[pos]
            
            if Self::h5_is_white(ch) {  // if (h5_is_white(ch))
                self.set_token(TokenType::AttrName, start_pos, scan_pos - start_pos);
                self.state_fn = Self::state_after_attribute_name;
                self.pos = scan_pos + 1;  // hs->pos = pos + 1
                return true;
            } else if ch == b'/' {  // ch == CHAR_SLASH
                self.set_token(TokenType::AttrName, start_pos, scan_pos - start_pos);
                self.state_fn = Self::state_self_closing_start_tag;
                self.pos = scan_pos + 1;  // hs->pos = pos + 1
                return true;
            } else if ch == b'=' {  // ch == CHAR_EQUALS
                self.set_token(TokenType::AttrName, start_pos, scan_pos - start_pos);
                self.state_fn = Self::state_before_attribute_value;
                self.pos = scan_pos + 1;  // hs->pos = pos + 1
                return true;
            } else if ch == b'>' {  // ch == CHAR_GT
                self.set_token(TokenType::AttrName, start_pos, scan_pos - start_pos);
                self.state_fn = Self::state_tag_name_close;  // Match C: hs->state = h5_state_tag_name_close;
                self.pos = scan_pos;  // hs->pos = pos (NOT pos + 1!)
                return true;
            } else {
                scan_pos += 1;  // pos += 1
            }
        }
        
        // EOF - match C lines 393-398 exactly
        self.set_token(TokenType::AttrName, start_pos, self.len - start_pos);
        self.state_fn = Self::state_eof;
        self.pos = self.len;  // hs->pos = hs->len
        true  // return 1
    }

    fn state_after_attribute_name(&mut self) -> bool {
        // Match C implementation exactly line by line
        match self.h5_skip_white() {  // c = h5_skip_white(hs)
            Some(-1) => false,  // case CHAR_EOF: return 0
            Some(0x2f) => {  // case CHAR_SLASH (47 as i8)
                self.pos += 1;  // hs->pos += 1
                self.state_self_closing_start_tag()  // return h5_state_self_closing_start_tag(hs)
            }
            Some(0x3d) => {  // case CHAR_EQUALS (61 as i8)
                self.pos += 1;  // hs->pos += 1
                self.state_before_attribute_value()  // return h5_state_before_attribute_value(hs)
            }
            Some(0x3e) => {  // case CHAR_GT (62 as i8)
                self.state_tag_name_close()  // return h5_state_tag_name_close(hs)
            }
            Some(_) => {  // default
                self.state_attribute_name()  // return h5_state_attribute_name(hs)
            }
            None => false,  // Should not happen with new implementation
        }
    }

    fn state_before_attribute_value(&mut self) -> bool {
        // Match C implementation exactly: c = h5_skip_white(hs)
        match self.h5_skip_white() {
            Some(-1) => {  // case CHAR_EOF
                self.state_fn = Self::state_eof;
                false
            }
            Some(0x22) => self.state_attribute_value_double_quote(),  // CHAR_DOUBLE (34)
            Some(0x27) => self.state_attribute_value_single_quote(),  // CHAR_SINGLE (39)
            Some(0x60) => self.state_attribute_value_back_quote(),    // CHAR_TICK (96)
            Some(_) => self.state_attribute_value_no_quote(),         // default
            None => {  // Should not happen with new implementation
                self.state_fn = Self::state_eof;
                false
            }
        }
    }

    fn state_attribute_value_double_quote(&mut self) -> bool {
        // Skip initial quote in normal case, but not if pos == 0 (non-data state start)
        if self.pos > 0 {
            self.advance();
        }
        
        let start = self.pos;
        if let Some(quote_pos) = self.find_byte(b'"', self.pos) {
            self.set_token(TokenType::AttrValue, start, quote_pos - start);
            self.pos = quote_pos + 1;
            self.state_fn = Self::state_after_attribute_value_quoted;
        } else {
            self.set_token(TokenType::AttrValue, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_attribute_value_single_quote(&mut self) -> bool {
        // Skip initial quote in normal case, but not if pos == 0 (non-data state start)
        if self.pos > 0 {
            self.advance();
        }
        
        let start = self.pos;
        if let Some(quote_pos) = self.find_byte(b'\'', self.pos) {
            self.set_token(TokenType::AttrValue, start, quote_pos - start);
            self.pos = quote_pos + 1;
            self.state_fn = Self::state_after_attribute_value_quoted;
        } else {
            self.set_token(TokenType::AttrValue, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_attribute_value_back_quote(&mut self) -> bool {
        // Skip initial quote in normal case, but not if pos == 0 (non-data state start)
        if self.pos > 0 {
            self.advance();
        }
        
        let start = self.pos;
        if let Some(quote_pos) = self.find_byte(b'`', self.pos) {
            self.set_token(TokenType::AttrValue, start, quote_pos - start);
            self.pos = quote_pos + 1;
            self.state_fn = Self::state_after_attribute_value_quoted;
        } else {
            self.set_token(TokenType::AttrValue, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_attribute_value_no_quote(&mut self) -> bool {
        let start = self.pos;
        while self.pos < self.len {
            let ch = self.s[self.pos];
            if Self::is_whitespace(ch) {
                self.set_token(TokenType::AttrValue, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_before_attribute_name;
                return true;
            } else if ch == b'>' {
                self.set_token(TokenType::AttrValue, start, self.pos - start);
                self.state_fn = Self::state_emit_tag_close_char;
                return true;
            }
            self.pos += 1;
        }
        
        // EOF
        self.set_token(TokenType::AttrValue, start, self.len - start);
        self.state_fn = Self::state_eof;
        true
    }

    fn state_after_attribute_value_quoted(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }
        
        let ch = self.current_char().unwrap_or(0);
        if Self::is_whitespace(ch) {
            self.advance();
            self.state_before_attribute_name()
        } else if ch == b'/' {
            self.advance();
            self.state_self_closing_start_tag()
        } else if ch == b'>' {
            self.set_token(TokenType::TagNameClose, self.pos, 1);
            self.advance();
            self.state_fn = Self::state_data;
            true
        } else {
            self.state_before_attribute_name()
        }
    }

    fn state_markup_declaration_open(&mut self) -> bool {
        if self.pos + 1 < self.len && self.s[self.pos] == b'-' && self.s[self.pos + 1] == b'-' {
            self.pos += 2;
            self.state_fn = Self::state_comment;
            self.next()
        } else if self.pos + 7 <= self.len {
            let slice = &self.s[self.pos..self.pos + 7];
            if slice.eq_ignore_ascii_case(b"DOCTYPE") {
                self.state_fn = Self::state_doctype;
                return self.next();
            } else if slice == b"[CDATA[" {
                self.pos += 7;
                self.state_fn = Self::state_cdata;
                self.next()
            } else {
                self.state_fn = Self::state_bogus_comment;
                self.next()
            }
        } else {
            self.state_fn = Self::state_bogus_comment;
            self.next()
        }
    }

    fn state_doctype(&mut self) -> bool {
        // Set token start to include "DOCTYPE"
        let start = self.pos;
        
        if let Some(gt_pos) = self.find_byte(b'>', self.pos) {
            self.set_token(TokenType::Doctype, start, gt_pos - start);
            self.pos = gt_pos + 1;
            self.state_fn = Self::state_data;
        } else {
            self.set_token(TokenType::Doctype, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_bogus_comment2(&mut self) -> bool {
        let start = self.pos;
        let mut pos = self.pos;
        
        loop {
            if let Some(percent_pos) = self.find_byte(b'%', pos) {
                if percent_pos + 1 >= self.len {
                    // No '>' after '%', consume to EOF
                    self.set_token(TokenType::TagComment, start, self.len - start);
                    self.pos = self.len;
                    self.state_fn = Self::state_eof;
                    return true;
                }
                
                if self.s[percent_pos + 1] == b'>' {
                    // Found "%>"
                    self.set_token(TokenType::TagComment, start, percent_pos - start);
                    self.pos = percent_pos + 2; // Skip "%>"
                    self.state_fn = Self::state_data;
                    return true;
                }
                
                pos = percent_pos + 1;
            } else {
                // No more '%' found, consume to EOF
                self.set_token(TokenType::TagComment, start, self.len - start);
                self.pos = self.len;
                self.state_fn = Self::state_eof;
                return true;
            }
        }
    }

    fn state_comment(&mut self) -> bool {
        let start = self.pos;
        
        if let Some((end_pos, offset)) = self.find_comment_end(self.pos) {
            self.set_token(TokenType::TagComment, start, end_pos - start);
            self.pos = end_pos + offset;
            self.state_fn = Self::state_data;
        } else {
            self.set_token(TokenType::TagComment, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_bogus_comment(&mut self) -> bool {
        let start = self.pos;
        
        if let Some(gt_pos) = self.find_byte(b'>', self.pos) {
            self.set_token(TokenType::TagComment, start, gt_pos - start);
            self.pos = gt_pos + 1;
            self.state_fn = Self::state_data;
        } else {
            self.set_token(TokenType::TagComment, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }

    fn state_cdata(&mut self) -> bool {
        let start = self.pos;
        
        if let Some(end_pos) = self.find_cdata_end(self.pos) {
            self.set_token(TokenType::DataText, start, end_pos - start);
            self.pos = end_pos + 3; // Skip "]]>"
            self.state_fn = Self::state_data;
        } else {
            self.set_token(TokenType::DataText, start, self.len - start);
            self.pos = self.len;
            self.state_fn = Self::state_eof;
        }
        true
    }
}