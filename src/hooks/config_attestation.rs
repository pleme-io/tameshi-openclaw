//! Configuration file attestation hooks for SOUL.md, AGENTS.md, HEARTBEAT.md.
//!
//! These hooks verify that OpenClaw's personality and agent definition files
//! have not been tampered with since the last attestation.

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use tameshi::hash::Blake3Hash;

use crate::core::types::GateDecision;
use crate::error::Result;

/// Attestation record for an OpenClaw configuration file.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigFileAttestation {
    /// File path relative to OpenClaw root.
    pub file_path: String,
    /// BLAKE3 hash of the file content.
    pub content_hash: String,
    /// When this attestation was computed.
    pub attested_at: chrono::DateTime<chrono::Utc>,
    /// Decision: whether the file matches expected hash.
    pub decision: GateDecision,
}

/// Configuration for config file attestation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigAttestationConfig {
    /// Expected hashes for each config file (path → blake3:hex).
    pub expected_hashes: std::collections::HashMap<String, String>,
}

/// Compute a BLAKE3 hash of file content and return as prefixed hex string.
#[must_use]
pub fn hash_config_content(content: &[u8]) -> String {
    Blake3Hash::digest(content).to_prefixed()
}

/// Verify a configuration file against its expected attestation hash.
#[must_use]
pub fn verify_config_file(
    file_path: &str,
    content: &[u8],
    config: &ConfigAttestationConfig,
) -> ConfigFileAttestation {
    let computed = hash_config_content(content);
    let decision = match config.expected_hashes.get(file_path) {
        Some(expected) if *expected == computed => GateDecision::Allow,
        Some(_) => GateDecision::Deny,
        None => GateDecision::Quarantine,
    };

    ConfigFileAttestation {
        file_path: file_path.into(),
        content_hash: computed,
        attested_at: Utc::now(),
        decision,
    }
}

/// Verify all OpenClaw configuration files (SOUL.md, AGENTS.md, HEARTBEAT.md).
pub async fn verify_all_configs(
    configs: &[(&str, &[u8])],
    attestation_config: &ConfigAttestationConfig,
) -> Result<Vec<ConfigFileAttestation>> {
    let results: Vec<ConfigFileAttestation> = configs
        .iter()
        .map(|(path, content)| verify_config_file(path, content, attestation_config))
        .collect();

    for result in &results {
        match result.decision {
            GateDecision::Allow => {
                tracing::info!(file = %result.file_path, "config file attestation passed");
            }
            GateDecision::Deny => {
                tracing::warn!(
                    file = %result.file_path,
                    hash = %result.content_hash,
                    "config file attestation FAILED — content has changed"
                );
            }
            GateDecision::Quarantine => {
                tracing::warn!(
                    file = %result.file_path,
                    "config file not in expected hashes — quarantined"
                );
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn soul_md_content() -> &'static [u8] {
        b"You are a helpful assistant named OpenClaw."
    }

    fn make_config_with_expected(path: &str, content: &[u8]) -> ConfigAttestationConfig {
        let mut expected = HashMap::new();
        expected.insert(path.into(), hash_config_content(content));
        ConfigAttestationConfig {
            expected_hashes: expected,
        }
    }

    #[test]
    fn hash_config_content_deterministic() {
        let h1 = hash_config_content(b"test content");
        let h2 = hash_config_content(b"test content");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
        assert_eq!(h1.len(), 71); // "blake3:" + 64 hex
    }

    #[test]
    fn hash_config_content_changes_on_different_content() {
        let h1 = hash_config_content(b"content A");
        let h2 = hash_config_content(b"content B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_config_file_allows_matching_hash() {
        let content = soul_md_content();
        let config = make_config_with_expected("SOUL.md", content);
        let result = verify_config_file("SOUL.md", content, &config);
        assert_eq!(result.decision, GateDecision::Allow);
        assert_eq!(result.file_path, "SOUL.md");
    }

    #[test]
    fn verify_config_file_denies_mismatched_hash() {
        let config = make_config_with_expected("SOUL.md", b"original content");
        let result = verify_config_file("SOUL.md", b"tampered content", &config);
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn verify_config_file_quarantines_unknown_file() {
        let config = ConfigAttestationConfig {
            expected_hashes: HashMap::new(),
        };
        let result = verify_config_file("UNKNOWN.md", b"anything", &config);
        assert_eq!(result.decision, GateDecision::Quarantine);
    }

    #[tokio::test]
    async fn verify_all_configs_processes_multiple_files() {
        let soul = soul_md_content();
        let agents = b"agent: assistant\nmodel: claude";
        let config = ConfigAttestationConfig {
            expected_hashes: {
                let mut h = HashMap::new();
                h.insert("SOUL.md".into(), hash_config_content(soul));
                h.insert("AGENTS.md".into(), hash_config_content(agents));
                h
            },
        };

        let configs: Vec<(&str, &[u8])> =
            vec![("SOUL.md", soul), ("AGENTS.md", agents)];
        let results = verify_all_configs(&configs, &config).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.decision == GateDecision::Allow));
    }

    #[tokio::test]
    async fn verify_all_configs_detects_drift() {
        let config = make_config_with_expected("SOUL.md", b"original");
        let configs: Vec<(&str, &[u8])> = vec![("SOUL.md", b"tampered")];
        let results = verify_all_configs(&configs, &config).await.unwrap();
        assert_eq!(results[0].decision, GateDecision::Deny);
    }
}
