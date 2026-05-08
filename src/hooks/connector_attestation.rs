//! Gateway connector attestation hooks.
//!
//! Verifies that platform gateway connectors (WhatsApp, Telegram, Discord, etc.)
//! carry valid attestation before relaying messages through the OpenClaw core.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use tameshi::hash::Blake3Hash;

use crate::core::types::GateDecision;

/// Platform connector identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorPlatform {
    WhatsApp,
    Telegram,
    Discord,
    Slack,
    Signal,
    #[serde(rename = "imessage")]
    IMessage,
    Custom(String),
}

/// Attestation record for a platform gateway connector.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConnectorAttestationRecord {
    /// Connector identifier.
    pub connector_id: String,
    /// Platform this connector serves.
    pub platform: ConnectorPlatform,
    /// BLAKE3 hash of the connector binary.
    pub binary_hash: String,
    /// BLAKE3 hash of the connector configuration.
    pub config_hash: String,
    /// Combined attestation hash (binary + config).
    pub composite_hash: String,
    /// When this attestation was computed.
    pub attested_at: DateTime<Utc>,
}

/// Expected connector attestation for verification.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExpectedConnector {
    /// Connector identifier.
    pub connector_id: String,
    /// Expected composite hash (blake3:hex).
    pub expected_hash: String,
    /// Platform for this connector.
    pub platform: ConnectorPlatform,
}

/// Compute composite hash from binary and config hashes.
#[must_use]
pub fn compute_connector_composite(binary_hash: &str, config_hash: &str) -> String {
    let mut combined = Vec::with_capacity(binary_hash.len() + config_hash.len());
    combined.extend_from_slice(binary_hash.as_bytes());
    combined.extend_from_slice(config_hash.as_bytes());
    Blake3Hash::digest(&combined).to_prefixed()
}

/// Verify a connector's attestation against expected hash.
#[must_use]
pub fn verify_connector(
    attestation: &ConnectorAttestationRecord,
    expected: &ExpectedConnector,
) -> GateDecision {
    if attestation.connector_id != expected.connector_id {
        return GateDecision::Deny;
    }
    if attestation.composite_hash == expected.expected_hash {
        GateDecision::Allow
    } else {
        GateDecision::Deny
    }
}

/// Verify all connectors against expected attestations.
/// Returns a list of (connector_id, decision) pairs.
#[must_use]
pub fn verify_all_connectors(
    attestations: &[ConnectorAttestationRecord],
    expected: &[ExpectedConnector],
) -> Vec<(String, GateDecision)> {
    let mut results = Vec::new();

    for exp in expected {
        let decision = match attestations
            .iter()
            .find(|a| a.connector_id == exp.connector_id)
        {
            Some(att) => verify_connector(att, exp),
            None => GateDecision::Deny, // Missing attestation = blocked
        };
        results.push((exp.connector_id.clone(), decision));
    }

    results
}

/// Check if a message from a specific connector should be relayed.
#[must_use]
pub fn should_relay_message(
    connector_id: &str,
    attestations: &[ConnectorAttestationRecord],
    expected: &[ExpectedConnector],
) -> GateDecision {
    let exp = match expected.iter().find(|e| e.connector_id == connector_id) {
        Some(e) => e,
        None => return GateDecision::Deny, // Unknown connector
    };

    match attestations.iter().find(|a| a.connector_id == connector_id) {
        Some(att) => verify_connector(att, exp),
        None => GateDecision::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(id: &str, platform: ConnectorPlatform) -> ConnectorAttestationRecord {
        let binary_hash = Blake3Hash::digest(b"binary").to_prefixed();
        let config_hash = Blake3Hash::digest(b"config").to_prefixed();
        let composite_hash = compute_connector_composite(&binary_hash, &config_hash);
        ConnectorAttestationRecord {
            connector_id: id.into(),
            platform,
            binary_hash,
            config_hash,
            composite_hash,
            attested_at: Utc::now(),
        }
    }

    fn make_expected(att: &ConnectorAttestationRecord) -> ExpectedConnector {
        ExpectedConnector {
            connector_id: att.connector_id.clone(),
            expected_hash: att.composite_hash.clone(),
            platform: att.platform.clone(),
        }
    }

    #[test]
    fn compute_composite_deterministic() {
        let h1 = compute_connector_composite("blake3:aaa", "blake3:bbb");
        let h2 = compute_connector_composite("blake3:aaa", "blake3:bbb");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
    }

    #[test]
    fn compute_composite_changes_on_input_change() {
        let h1 = compute_connector_composite("blake3:aaa", "blake3:bbb");
        let h2 = compute_connector_composite("blake3:aaa", "blake3:ccc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_connector_allows_matching() {
        let att = make_attestation("wa-1", ConnectorPlatform::WhatsApp);
        let exp = make_expected(&att);
        assert_eq!(verify_connector(&att, &exp), GateDecision::Allow);
    }

    #[test]
    fn verify_connector_denies_mismatched_hash() {
        let att = make_attestation("wa-1", ConnectorPlatform::WhatsApp);
        let exp = ExpectedConnector {
            connector_id: "wa-1".into(),
            expected_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000".into(),
            platform: ConnectorPlatform::WhatsApp,
        };
        assert_eq!(verify_connector(&att, &exp), GateDecision::Deny);
    }

    #[test]
    fn verify_connector_denies_wrong_id() {
        let att = make_attestation("wa-1", ConnectorPlatform::WhatsApp);
        let exp = ExpectedConnector {
            connector_id: "wa-2".into(),
            expected_hash: att.composite_hash.clone(),
            platform: ConnectorPlatform::WhatsApp,
        };
        assert_eq!(verify_connector(&att, &exp), GateDecision::Deny);
    }

    #[test]
    fn verify_all_connectors_handles_missing() {
        let att = make_attestation("wa-1", ConnectorPlatform::WhatsApp);
        let expected = vec![
            make_expected(&att),
            ExpectedConnector {
                connector_id: "tg-1".into(),
                expected_hash: "blake3:missing".into(),
                platform: ConnectorPlatform::Telegram,
            },
        ];
        let results = verify_all_connectors(&[att], &expected);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, GateDecision::Allow);
        assert_eq!(results[1].1, GateDecision::Deny);
    }

    #[test]
    fn should_relay_allows_attested_connector() {
        let att = make_attestation("dc-1", ConnectorPlatform::Discord);
        let expected = vec![make_expected(&att)];
        assert_eq!(
            should_relay_message("dc-1", &[att], &expected),
            GateDecision::Allow
        );
    }

    #[test]
    fn should_relay_denies_unknown_connector() {
        assert_eq!(
            should_relay_message("unknown", &[], &[]),
            GateDecision::Deny
        );
    }

    #[test]
    fn connector_platform_serde_roundtrip() {
        let platforms = vec![
            ConnectorPlatform::WhatsApp,
            ConnectorPlatform::Telegram,
            ConnectorPlatform::Discord,
            ConnectorPlatform::Slack,
            ConnectorPlatform::Signal,
            ConnectorPlatform::IMessage,
            ConnectorPlatform::Custom("matrix".into()),
        ];
        for p in &platforms {
            let json = serde_json::to_string(p).unwrap();
            let parsed: ConnectorPlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, p);
        }
    }
}
