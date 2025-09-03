#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
//!
//! ## API Guide
//!
//! ### For End Users
//!
//! Most applications should use the high-level detection functions:
//!
//! - [`detect_sqli`] - Main SQL injection detection (recommended)
//! - [`detect_sqli_with_flags`] - SQL injection detection with custom flags
//! - [`detect_xss`] - Cross-site scripting detection
//! - [`version`] - Library version information
//!
//! These functions handle all the complexity of testing multiple contexts and
//! SQL dialects automatically, returning simple results.
//!
//! ### For Advanced Users and Debugging
//!
//! For debugging, performance analysis, or advanced customization, you can access
//! the lower-level APIs:
//!
//! - [`SqliState`] - Direct access to SQL parsing state and tokenization
//! - [`XssDetector`] - Direct XSS detection with context control
//! - [`Fingerprint`] - SQL injection fingerprint analysis
//!
//! These APIs expose the internal parsing state, tokens, and folding mechanisms
//! that power the detection logic. They are primarily intended for:
//!
//! - **Debugging**: Understanding why certain inputs are flagged
//! - **Performance**: Avoiding repeated parsing for multiple checks
//! - **Research**: Analyzing the tokenization and folding process
//! - **Testing**: Validating behavior against the C reference implementation
//!
//! Most applications should **not** use these lower-level APIs unless they have
//! specific requirements that the high-level functions cannot meet.

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




// Re-export types for advanced usage
pub use sqli::{SqliState, SqliFlags, Fingerprint};
pub use xss::{XssDetector, XssResult};

/// The type of injection detected by libinjection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionType {
    /// SQL injection
    Sqli,
    /// Cross-site scripting (XSS)
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

/// Result of an injection detection operation.
/// 
/// This structure contains information about whether injection was detected,
/// what type it was, and additional metadata like the fingerprint.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionResult {
    /// The type of injection detected (SQL or XSS)
    pub injection_type: InjectionType,
    is_injection: bool,
    /// SQL injection fingerprint, if applicable and detected
    pub fingerprint: Option<Fingerprint>,
    /// Confidence level (currently binary: 1.0 for injection, 0.0 for safe)
    pub confidence: f32,
}

impl DetectionResult {
    /// Returns `true` if injection was detected, `false` otherwise.
    pub fn is_injection(&self) -> bool {
        self.is_injection
    }
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

/// Detects SQL injection in the given input using default flags.
///
/// This is the main entry point for SQL injection detection. It tests the input
/// in multiple contexts (no quotes, single quotes, double quotes) and with both
/// ANSI and MySQL SQL modes to maximize detection accuracy.
///
/// # Arguments
///
/// * `input` - The byte slice to analyze for SQL injection
///
/// # Returns
///
/// Returns a [`DetectionResult`] indicating whether injection was detected,
/// along with the fingerprint if it was SQL injection.
///
/// # Examples
///
/// ```
/// use libinjectionrs::detect_sqli;
///
/// // Safe input
/// let result = detect_sqli(b"hello world");
/// assert!(!result.is_injection());
///
/// // SQL injection
/// let result = detect_sqli(b"1' OR '1'='1");
/// assert!(result.is_injection());
/// ```
pub fn detect_sqli(input: &[u8]) -> DetectionResult {
    detect_sqli_with_flags(input, SqliFlags::FLAG_NONE)
}

/// Detects SQL injection in the given input with specific parsing flags.
///
/// This function allows you to customize the SQL parsing behavior by specifying
/// flags for quote context and SQL dialect. However, for most use cases,
/// [`detect_sqli`] is recommended as it automatically tests multiple contexts.
///
/// # Arguments
///
/// * `input` - The byte slice to analyze for SQL injection
/// * `flags` - Parsing flags to control quote context and SQL dialect
///
/// # Returns
///
/// Returns a [`DetectionResult`] indicating whether injection was detected.
///
/// # Examples
///
/// ```
/// use libinjectionrs::{detect_sqli_with_flags, SqliFlags};
///
/// let result = detect_sqli_with_flags(
///     b"1' OR '1'='1", 
///     SqliFlags::FLAG_QUOTE_SINGLE | SqliFlags::FLAG_SQL_ANSI
/// );
/// assert!(result.is_injection());
/// ```
pub fn detect_sqli_with_flags(input: &[u8], flags: SqliFlags) -> DetectionResult {
    let mut state = SqliState::new(input, flags);
    let is_sqli = state.detect();
    let fp = state.get_fingerprint();
    
    DetectionResult {
        is_injection: is_sqli,
        injection_type: InjectionType::Sqli,
        fingerprint: Some(fp),
        confidence: if is_sqli { 1.0 } else { 0.0 },
    }
}

/// Detects Cross-Site Scripting (XSS) in the given input.
///
/// This function analyzes the input for XSS vectors by parsing it in multiple
/// HTML contexts (data state, unquoted attributes, single/double quoted attributes,
/// etc.) to detect potentially malicious HTML, JavaScript, or other markup.
///
/// # Arguments
///
/// * `input` - The byte slice to analyze for XSS
///
/// # Returns
///
/// Returns an [`XssResult`] indicating whether XSS was detected.
///
/// # Examples
///
/// ```
/// use libinjectionrs::detect_xss;
///
/// // Safe input
/// let result = detect_xss(b"Hello, world!");
/// assert!(!result.is_injection());
///
/// // XSS vector
/// let result = detect_xss(b"<script>alert('xss')</script>");
/// assert!(result.is_injection());
/// ```
pub fn detect_xss(input: &[u8]) -> XssResult {
    XssDetector::new().detect(input)
}

/// Returns the version of the libinjection library.
///
/// # Examples
///
/// ```
/// use libinjectionrs::version;
/// 
/// println!("libinjection version: {}", version());
/// ```
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}