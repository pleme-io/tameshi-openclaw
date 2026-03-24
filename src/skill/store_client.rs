use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreSkill {
    pub id: String,
    pub name: String,
    pub version: String,
    pub attestation_hash: String,
    pub status: String,
}

/// Client for the OpenClaw attested skill store.
pub struct StoreClient {
    base_url: String,
    client: reqwest::Client,
}

impl StoreClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// List available skills from the store.
    pub async fn list_skills(&self) -> Result<Vec<StoreSkill>> {
        let url = format!("{}/api/v1/skills", self.base_url);
        let resp = self.client.get(&url).send().await?;
        let skills: Vec<StoreSkill> = resp.json().await?;
        Ok(skills)
    }

    /// Verify a skill's attestation is still valid.
    pub async fn verify_skill(&self, skill_id: &str) -> Result<bool> {
        let url = format!("{}/api/v1/skills/{skill_id}/verify", self.base_url);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }
}
