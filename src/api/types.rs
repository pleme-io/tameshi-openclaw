use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateRequest {
    pub skill_name: String,
    pub source_code: String,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateResponse {
    pub allowed: bool,
    pub attestation_hash: Option<String>,
    pub reasons: Vec<String>,
}
