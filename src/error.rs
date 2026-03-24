use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenClawError {
    #[error("attestation failed: {0}")]
    AttestationFailed(String),
    #[error("compliance check failed: {0}")]
    ComplianceFailed(String),
    #[error("skill gate denied: {0}")]
    SkillGateDenied(String),
    #[error("store error: {0}")]
    StoreError(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("scanner error: {0}")]
    ScannerError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, OpenClawError>;
