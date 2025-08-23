use core::fmt;

pub struct XssDetector {
    flags: u32,
}

impl Default for XssDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl XssDetector {
    pub fn new() -> Self {
        Self { flags: 0 }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn detect(&self, input: &[u8]) -> XssResult {
        let mut state = XssState::new(input, self.flags);
        
        if state.analyze() {
            XssResult::Injection {
                context: state.get_context(),
            }
        } else {
            XssResult::Safe
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum XssResult {
    Safe,
    Injection { context: XssContext },
}

impl XssResult {
    pub fn is_injection(&self) -> bool {
        matches!(self, XssResult::Injection { .. })
    }

    pub fn context(&self) -> Option<&XssContext> {
        match self {
            XssResult::Injection { context } => Some(context),
            XssResult::Safe => None,
        }
    }
}

impl fmt::Display for XssResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XssResult::Safe => write!(f, "Safe"),
            XssResult::Injection { context } => {
                write!(f, "XSS detected in {} context", context)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XssContext {
    Html,
    Attribute,
    JavaScript,
    Url,
    Style,
    Unknown,
}

impl fmt::Display for XssContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XssContext::Html => write!(f, "HTML"),
            XssContext::Attribute => write!(f, "attribute"),
            XssContext::JavaScript => write!(f, "JavaScript"),
            XssContext::Url => write!(f, "URL"),
            XssContext::Style => write!(f, "CSS"),
            XssContext::Unknown => write!(f, "unknown"),
        }
    }
}

struct XssState<'a> {
    input: &'a [u8],
    flags: u32,
    pos: usize,
    context: XssContext,
    in_tag: bool,
    in_attr: bool,
    in_script: bool,
    in_style: bool,
}

impl<'a> XssState<'a> {
    fn new(input: &'a [u8], flags: u32) -> Self {
        Self {
            input,
            flags,
            pos: 0,
            context: XssContext::Unknown,
            in_tag: false,
            in_attr: false,
            in_script: false,
            in_style: false,
        }
    }

    fn analyze(&mut self) -> bool {
        // Match C implementation: only detect XSS within HTML contexts
        // Plain text like "javascript:alert(1)" should NOT be flagged
        
        let input_str = String::from_utf8_lossy(self.input).to_lowercase();
        
        // Only look for XSS if we have HTML structure
        if !input_str.contains('<') {
            return false; // No HTML, no XSS (matches C behavior)
        }
        
        // Check for dangerous HTML tags (these are always dangerous)
        if input_str.contains("<script") || 
           input_str.contains("<iframe") ||
           input_str.contains("<embed") ||
           input_str.contains("<object") ||
           input_str.contains("<applet") ||
           input_str.contains("<svg") {
            self.context = XssContext::Html;
            return true;
        }
        
        // Check for dangerous patterns within HTML attributes
        // This is a simplified version - should be proper HTML parsing
        if self.has_dangerous_attributes(&input_str) {
            return true;
        }
        
        false
    }

    fn check_tag_start(&mut self) -> bool {
        if self.pos + 6 < self.input.len() {
            let next_bytes = &self.input[self.pos + 1..self.pos + 7];
            
            if next_bytes.eq_ignore_ascii_case(b"script") {
                self.in_script = true;
                self.context = XssContext::JavaScript;
                return true;
            }
            
            if next_bytes.eq_ignore_ascii_case(b"style") {
                self.in_style = true;
                self.context = XssContext::Style;
                return false;
            }
            
            if self.pos + 4 < self.input.len() {
                let img_bytes = &self.input[self.pos + 1..self.pos + 4];
                if img_bytes.eq_ignore_ascii_case(b"img") {
                    self.in_tag = true;
                    self.context = XssContext::Html;
                    return false;
                }
            }
            
            if self.pos + 7 < self.input.len() {
                let iframe_bytes = &self.input[self.pos + 1..self.pos + 7];
                if iframe_bytes.eq_ignore_ascii_case(b"iframe") {
                    self.in_tag = true;
                    self.context = XssContext::Html;
                    return true;
                }
            }
        }
        
        self.in_tag = true;
        false
    }

    fn check_attr_break(&mut self, quote: u8) -> bool {
        let mut i = self.pos + 1;
        let mut found_close = false;
        
        while i < self.input.len() {
            if self.input[i] == quote {
                found_close = true;
                break;
            }
            if self.input[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        
        if found_close && i + 1 < self.input.len() {
            let next = self.input[i + 1];
            if next == b'>' || next.is_ascii_whitespace() {
                self.context = XssContext::Attribute;
                return true;
            }
        }
        
        false
    }

    fn check_javascript(&mut self) -> bool {
        if self.pos + 10 < self.input.len() {
            let bytes = &self.input[self.pos..self.pos + 10];
            if bytes.eq_ignore_ascii_case(b"javascript") {
                self.context = XssContext::JavaScript;
                return true;
            }
        }
        false
    }

    fn check_event_handler(&mut self) -> bool {
        if self.in_tag && self.pos + 7 < self.input.len() {
            let bytes = &self.input[self.pos..self.pos + 7];
            
            if bytes[..2].eq_ignore_ascii_case(b"on") {
                let handler = &bytes[2..];
                for event in [b"click".as_ref(), b"load".as_ref(), b"error".as_ref(), b"mouse".as_ref(), b"focus".as_ref()].iter() {
                    if handler.len() >= event.len() 
                        && handler[..event.len()].eq_ignore_ascii_case(event) {
                        self.context = XssContext::JavaScript;
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_dangerous_attributes(&mut self, input_str: &str) -> bool {
        // Look for dangerous patterns within HTML attribute contexts
        // This is a simplified approximation of the C HTML5 parser logic
        
        // Pattern: href="javascript:...", src="javascript:...", etc.
        if (input_str.contains("href=") || input_str.contains("src=")) {
            if input_str.contains("javascript:") || 
               input_str.contains("vbscript:") ||
               input_str.contains("data:") {
                self.context = XssContext::Url;
                return true;
            }
        }
        
        // Event handlers in attributes: onload="...", onclick="...", etc.
        if input_str.contains("onload=") ||
           input_str.contains("onerror=") ||
           input_str.contains("onclick=") ||
           input_str.contains("onmouseover=") ||
           input_str.contains("onfocus=") ||
           input_str.contains("onblur=") {
            self.context = XssContext::JavaScript;
            return true;
        }
        
        // Style attributes with dangerous CSS
        if input_str.contains("style=") && 
           (input_str.contains("expression(") ||
            input_str.contains("behavior:")) {
            self.context = XssContext::Style;
            return true;
        }
        
        false
    }

    fn get_context(&self) -> XssContext {
        self.context
    }
}