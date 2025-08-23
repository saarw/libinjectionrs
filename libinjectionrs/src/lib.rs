#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../../README.md")]

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

pub mod sqli;
pub mod xss;

pub use sqli::{SqliDetector, SqliResult};
pub use xss::{XssDetector, XssResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionType {
    Sqli,
    Xss,
}

impl fmt::Display for InjectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectionType::Sqli => write!(f, "SQL Injection"),
            InjectionType::Xss => write!(f, "XSS"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetectionResult {
    pub injection_type: InjectionType,
    pub is_injection: bool,
    pub fingerprint: Option<Fingerprint>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    inner: [u8; 8],
}

impl Fingerprint {
    pub fn new(data: [u8; 8]) -> Self {
        Self { inner: data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.inner)
            .unwrap_or("")
            .trim_end_matches('\0')
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidInput(&'static str),
    ParseError(ParseError),
    #[cfg(feature = "std")]
    Io(String),
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: &'static str,
    pub position: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::ParseError(pe) => write!(f, "Parse error at position {}: {}", pe.position, pe.message),
            #[cfg(feature = "std")]
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {}

pub fn detect_sqli(input: &[u8]) -> SqliResult {
    SqliDetector::new().detect(input)
}

pub fn detect_xss(input: &[u8]) -> XssResult {
    XssDetector::new().detect(input)
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}