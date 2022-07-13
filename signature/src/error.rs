use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Error {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    Uncategorized,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct SignatureError {
    pub message: String,
    pub kind: ErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, self.message)
    }
}

impl SignatureError {
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            message: String::from(""),
            kind: kind,
            source: None,
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for SignatureError {
    fn from(source: Box<dyn std::error::Error + Send + Sync + 'static>) -> SignatureError {
        SignatureError {
            message: String::from(""),
            kind: ErrorKind::Uncategorized,
            source: Some(source),
        }
    }
}

impl std::error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        return self
            .source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static));
    }
}

impl From<ed25519_zebra::Error> for SignatureError {
    fn from(e: ed25519_zebra::Error) -> Self {
        SignatureError {
            message: e.to_string(),
            kind: ErrorKind::Uncategorized,
            source: None,
        }
    }
}
