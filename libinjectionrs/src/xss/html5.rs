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
        }
    }

    pub fn next(&mut self) -> bool {
        (self.state_fn)(self)
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

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.current_char() {
            if Self::is_whitespace(ch) {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn is_whitespace(ch: u8) -> bool {
        matches!(ch, b' ' | b'\t' | b'\n' | b'\r' | b'\x0C')
    }

    fn state_eof(&mut self) -> bool {
        false
    }

    fn state_data(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'<' {
                if self.pos > start {
                    self.set_token(TokenType::DataText, start, self.pos - start);
                    return true;
                } else {
                    self.advance();
                    self.state_fn = Self::state_tag_open;
                    return self.next();
                }
            }
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::DataText, start, self.pos - start);
            true
        } else {
            false
        }
    }

    fn state_tag_open(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap() {
            b'!' => {
                self.advance();
                self.state_fn = Self::state_markup_declaration_open;
                self.next()
            }
            b'/' => {
                self.advance();
                self.state_fn = Self::state_end_tag_open;
                self.next()
            }
            b'?' => {
                self.advance();
                self.state_fn = Self::state_bogus_comment;
                self.next()
            }
            ch if ch.is_ascii_alphabetic() => {
                self.state_fn = Self::state_tag_name;
                self.next()
            }
            _ => {
                self.state_fn = Self::state_data;
                self.next()
            }
        }
    }

    fn state_tag_name(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            match ch {
                b'/' => {
                    if self.pos > start {
                        self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                        self.state_fn = Self::state_self_closing_start_tag;
                        return true;
                    }
                    break;
                }
                b'>' => {
                    if self.pos > start {
                        self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                        self.advance();
                        self.state_fn = Self::state_data;
                        return true;
                    }
                    break;
                }
                ch if Self::is_whitespace(ch) => {
                    if self.pos > start {
                        self.set_token(TokenType::TagNameOpen, start, self.pos - start);
                        self.state_fn = Self::state_before_attribute_name;
                        return true;
                    }
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }

        if self.pos > start {
            self.set_token(TokenType::TagNameOpen, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_end_tag_open(&mut self) -> bool {
        if self.is_eof() {
            return false;
        }

        if self.current_char().unwrap().is_ascii_alphabetic() {
            self.state_fn = Self::state_tag_name_close;
            self.next()
        } else {
            self.state_fn = Self::state_bogus_comment;
            self.next()
        }
    }

    fn state_tag_name_close(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            match ch {
                b'>' => {
                    if self.pos > start {
                        self.set_token(TokenType::TagNameClose, start, self.pos - start);
                        self.advance();
                        self.state_fn = Self::state_data;
                        return true;
                    }
                    break;
                }
                ch if Self::is_whitespace(ch) => {
                    if self.pos > start {
                        self.set_token(TokenType::TagNameClose, start, self.pos - start);
                        self.skip_whitespace();
                        if self.current_char() == Some(b'>') {
                            self.advance();
                            self.state_fn = Self::state_data;
                        } else {
                            self.state_fn = Self::state_eof;
                        }
                        return true;
                    }
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }

        if self.pos > start {
            self.set_token(TokenType::TagNameClose, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_self_closing_start_tag(&mut self) -> bool {
        self.skip_whitespace();
        if self.current_char() == Some(b'>') {
            self.advance();
            self.state_fn = Self::state_data;
            self.next()
        } else {
            self.state_fn = Self::state_before_attribute_name;
            self.next()
        }
    }

    fn state_before_attribute_name(&mut self) -> bool {
        self.skip_whitespace();

        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap() {
            b'/' => {
                self.advance();
                self.state_fn = Self::state_self_closing_start_tag;
                self.next()
            }
            b'>' => {
                self.advance();
                self.state_fn = Self::state_data;
                self.next()
            }
            b'=' => {
                self.advance();
                self.state_fn = Self::state_before_attribute_name;
                self.next()
            }
            _ => {
                self.state_fn = Self::state_attribute_name;
                self.next()
            }
        }
    }

    fn state_attribute_name(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            match ch {
                b'/' | b'>' => {
                    if self.pos > start {
                        self.set_token(TokenType::AttrName, start, self.pos - start);
                        self.state_fn = Self::state_after_attribute_name;
                        return true;
                    }
                    break;
                }
                b'=' => {
                    if self.pos > start {
                        self.set_token(TokenType::AttrName, start, self.pos - start);
                        self.advance();
                        self.state_fn = Self::state_before_attribute_value;
                        return true;
                    }
                    break;
                }
                ch if Self::is_whitespace(ch) => {
                    if self.pos > start {
                        self.set_token(TokenType::AttrName, start, self.pos - start);
                        self.state_fn = Self::state_after_attribute_name;
                        return true;
                    }
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }

        if self.pos > start {
            self.set_token(TokenType::AttrName, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_after_attribute_name(&mut self) -> bool {
        self.skip_whitespace();

        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap() {
            b'/' => {
                self.advance();
                self.state_fn = Self::state_self_closing_start_tag;
                self.next()
            }
            b'>' => {
                self.advance();
                self.state_fn = Self::state_data;
                self.next()
            }
            b'=' => {
                self.advance();
                self.state_fn = Self::state_before_attribute_value;
                self.next()
            }
            _ => {
                self.state_fn = Self::state_attribute_name;
                self.next()
            }
        }
    }

    fn state_before_attribute_value(&mut self) -> bool {
        self.skip_whitespace();

        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap() {
            b'"' => {
                self.advance();
                self.state_fn = Self::state_attribute_value_double_quote;
                self.next()
            }
            b'\'' => {
                self.advance();
                self.state_fn = Self::state_attribute_value_single_quote;
                self.next()
            }
            b'`' => {
                self.advance();
                self.state_fn = Self::state_attribute_value_back_quote;
                self.next()
            }
            b'>' => {
                self.advance();
                self.state_fn = Self::state_data;
                self.next()
            }
            _ => {
                self.state_fn = Self::state_attribute_value_no_quote;
                self.next()
            }
        }
    }

    fn state_attribute_value_double_quote(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'"' {
                self.set_token(TokenType::AttrValue, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_after_attribute_value_quoted;
                return true;
            }
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::AttrValue, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_attribute_value_single_quote(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'\'' {
                self.set_token(TokenType::AttrValue, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_after_attribute_value_quoted;
                return true;
            }
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::AttrValue, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_attribute_value_back_quote(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'`' {
                self.set_token(TokenType::AttrValue, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_after_attribute_value_quoted;
                return true;
            }
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::AttrValue, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_attribute_value_no_quote(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            match ch {
                ch if Self::is_whitespace(ch) => {
                    if self.pos > start {
                        self.set_token(TokenType::AttrValue, start, self.pos - start);
                        self.state_fn = Self::state_before_attribute_name;
                        return true;
                    }
                    break;
                }
                b'>' => {
                    if self.pos > start {
                        self.set_token(TokenType::AttrValue, start, self.pos - start);
                        self.advance();
                        self.state_fn = Self::state_data;
                        return true;
                    }
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }

        if self.pos > start {
            self.set_token(TokenType::AttrValue, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_after_attribute_value_quoted(&mut self) -> bool {
        self.skip_whitespace();

        if self.is_eof() {
            return false;
        }

        match self.current_char().unwrap() {
            b'/' => {
                self.advance();
                self.state_fn = Self::state_self_closing_start_tag;
                self.next()
            }
            b'>' => {
                self.advance();
                self.state_fn = Self::state_data;
                self.next()
            }
            _ => {
                self.state_fn = Self::state_before_attribute_name;
                self.next()
            }
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
                self.pos += 7;
                self.state_fn = Self::state_doctype;
                self.next()
            } else if slice.eq_ignore_ascii_case(b"[CDATA[") {
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
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'>' {
                self.set_token(TokenType::Doctype, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_data;
                return true;
            }
            self.advance();
        }

        self.set_token(TokenType::Doctype, start, self.pos - start);
        self.state_fn = Self::state_eof;
        true
    }

    fn state_comment(&mut self) -> bool {
        let start = self.pos;
        while self.pos + 2 < self.len {
            if self.s[self.pos] == b'-' && self.s[self.pos + 1] == b'-' && self.s[self.pos + 2] == b'>' {
                self.set_token(TokenType::TagComment, start, self.pos - start);
                self.pos += 3;
                self.state_fn = Self::state_data;
                return true;
            }
            self.advance();
        }

        // Handle end of input within comment
        while let Some(_) = self.current_char() {
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::TagComment, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_bogus_comment(&mut self) -> bool {
        let start = self.pos;
        while let Some(ch) = self.current_char() {
            if ch == b'>' {
                self.set_token(TokenType::TagComment, start, self.pos - start);
                self.advance();
                self.state_fn = Self::state_data;
                return true;
            }
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::TagComment, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }

    fn state_cdata(&mut self) -> bool {
        let start = self.pos;
        while self.pos + 2 < self.len {
            if self.s[self.pos] == b']' && self.s[self.pos + 1] == b']' && self.s[self.pos + 2] == b'>' {
                self.set_token(TokenType::DataText, start, self.pos - start);
                self.pos += 3;
                self.state_fn = Self::state_data;
                return true;
            }
            self.advance();
        }

        // Handle end of input within CDATA
        while let Some(_) = self.current_char() {
            self.advance();
        }

        if self.pos > start {
            self.set_token(TokenType::DataText, start, self.pos - start);
            self.state_fn = Self::state_eof;
            true
        } else {
            false
        }
    }
}