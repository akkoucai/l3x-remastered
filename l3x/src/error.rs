use thiserror::Error;

#[derive(Error, Debug)]
pub enum MyError {
    #[error("IO Error")]
    Io(#[from] std::io::Error),

    #[error("Reqwest Error")]
    Reqwest(#[from] reqwest::Error),

    #[error("Serde Json Error")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Regex Error")]
    Regex(#[from] regex::Error),

    #[error("Custom Error: {0}")]
    Custom(String),

    #[error("Other Error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl MyError {
    pub fn custom(msg: impl Into<String>) -> Self {
        MyError::Custom(msg.into())
    }
}
