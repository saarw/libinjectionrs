#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../../README.md")]

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

pub mod sqli;
pub mod xss;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod final_test;


pub use sqli::{SqliState, SqliFlags, Fingerprint};
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

// Fingerprint is now exported from sqli module

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

pub fn detect_sqli(input: &[u8]) -> DetectionResult {
    let mut state = SqliState::new(input, SqliFlags::FLAG_SQL_ANSI);
    let is_sqli = state.detect();
    let fp = state.get_fingerprint();
    
    DetectionResult {
        is_injection: is_sqli,
        injection_type: InjectionType::Sqli,
        fingerprint: Some(fp),
        confidence: if is_sqli { 1.0 } else { 0.0 },
    }
}

pub fn detect_xss(input: &[u8]) -> XssResult {
    XssDetector::new().detect(input)
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}