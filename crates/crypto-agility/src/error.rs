use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoAgilityError>;

#[derive(Debug, Error)]
pub enum CryptoAgilityError {
    #[error("No compatible crypto suite")]
    NoCommonSuite,
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(i32),
    #[error("{0}")]
    Other(String),
}
