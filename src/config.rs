use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizedModel {
    pub provider: String,
    pub model_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenClawConfig {
    pub agent_name: String,
    pub skills_dir: String,
    pub config_path: String,
    pub store_url: Option<String>,
    pub scan_interval_secs: u64,
    pub allowed_permissions: Vec<String>,
    #[serde(default)]
    pub authorized_models: Vec<AuthorizedModel>,
}
