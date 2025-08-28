pub use self::detector::{XssDetector, XssResult};
pub use self::html5::{Html5State, Html5Flags, TokenType};
pub use self::blacklists::AttributeType;

mod detector;
mod html5;
mod blacklists;

#[cfg(test)]
mod tests;