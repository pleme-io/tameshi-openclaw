//! MCPS bridge — bridges MCP Secure (MCPS) passport issuance to tameshi certification.
//!
//! An MCPS passport is a time-bounded attestation token that certifies an AI agent
//! has passed the required compliance frameworks and holds a valid composite hash
//! from the tameshi Merkle tree.

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An MCPS passport issued to an AI agent after successful attestation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct McpsPassport {
    /// Unique identifier of the agent this passport was issued to.
    pub agent_id: String,
    /// Composite BLAKE3 hash from the tameshi attestation tree.
    pub composite_hash: String,
    /// When the passport was issued.
    pub issued_at: DateTime<Utc>,
    /// When the passport expires.
    pub expires_at: DateTime<Utc>,
    /// Compliance frameworks the agent passed during attestation.
    pub frameworks_passed: Vec<String>,
}

/// Configuration for MCPS passport issuance.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct McpsConfig {
    /// Identifier of the issuing authority.
    pub issuer_id: String,
    /// Time-to-live for issued passports in seconds.
    #[serde(default = "default_passport_ttl_secs")]
    pub passport_ttl_secs: u64,
}

const fn default_passport_ttl_secs() -> u64 {
    3600
}

/// Issue an MCPS passport for an agent that has passed attestation.
///
/// The passport captures the composite hash, the list of frameworks that
/// passed, and a validity window derived from the configured TTL.
#[must_use]
pub fn issue_passport(
    config: &McpsConfig,
    agent_id: &str,
    composite_hash: &str,
    frameworks: &[String],
) -> McpsPassport {
    let now = Utc::now();
    let ttl = Duration::seconds(
        i64::try_from(config.passport_ttl_secs).unwrap_or(3600),
    );

    McpsPassport {
        agent_id: agent_id.to_owned(),
        composite_hash: composite_hash.to_owned(),
        issued_at: now,
        expires_at: now + ttl,
        frameworks_passed: frameworks.to_vec(),
    }
}

/// Verify that an MCPS passport is still valid.
///
/// A passport is valid when:
/// 1. It has not expired (current time < `expires_at`).
/// 2. It has at least one framework in `frameworks_passed`.
/// 3. The `composite_hash` starts with "blake3:" and is exactly 71 characters
///    ("blake3:" prefix + 64 hex digits).
#[must_use]
pub fn verify_passport(passport: &McpsPassport) -> bool {
    let now = Utc::now();
    let hash_valid =
        passport.composite_hash.starts_with("blake3:") && passport.composite_hash.len() == 71;
    now < passport.expires_at && !passport.frameworks_passed.is_empty() && hash_valid
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid blake3-prefixed hash for test use (71 chars: "blake3:" + 64 hex).
    const VALID_HASH: &str =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000";

    fn test_config() -> McpsConfig {
        McpsConfig {
            issuer_id: "tameshi-test".into(),
            passport_ttl_secs: 3600,
        }
    }

    #[test]
    fn passport_issuance() {
        let config = test_config();
        let frameworks = vec!["nist_ai_rmf".into(), "eu_ai_act".into()];
        let passport = issue_passport(&config, "agent-001", VALID_HASH, &frameworks);

        assert_eq!(passport.agent_id, "agent-001");
        assert_eq!(passport.composite_hash, VALID_HASH);
        assert_eq!(passport.frameworks_passed.len(), 2);
        assert!(passport.expires_at > passport.issued_at);
    }

    #[test]
    fn passport_expiry_verification() {
        let config = test_config();
        let frameworks = vec!["nist_ai_rmf".into()];

        // Fresh passport should be valid.
        let passport = issue_passport(&config, "agent-002", VALID_HASH, &frameworks);
        assert!(verify_passport(&passport));

        // Manually expired passport should be invalid.
        let expired = McpsPassport {
            agent_id: "agent-003".into(),
            composite_hash: VALID_HASH.into(),
            issued_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            frameworks_passed: vec!["nist_ai_rmf".into()],
        };
        assert!(!verify_passport(&expired));
    }

    #[test]
    fn passport_without_frameworks_is_invalid() {
        let config = test_config();
        let passport = issue_passport(&config, "agent-004", VALID_HASH, &[]);
        assert!(!verify_passport(&passport));
    }

    #[test]
    fn passport_with_invalid_hash_is_invalid() {
        let config = test_config();
        let frameworks = vec!["nist_ai_rmf".into()];
        // Hash without blake3: prefix should fail validation.
        let passport = issue_passport(&config, "agent-006", "not_a_valid_hash", &frameworks);
        assert!(!verify_passport(&passport));
    }

    #[test]
    fn passport_with_short_hash_is_invalid() {
        let config = test_config();
        let frameworks = vec!["nist_ai_rmf".into()];
        // Right prefix but wrong length.
        let passport = issue_passport(&config, "agent-007", "blake3:tooshort", &frameworks);
        assert!(!verify_passport(&passport));
    }

    #[test]
    fn config_default_ttl() {
        let json = r#"{"issuer_id": "test-issuer"}"#;
        let config: McpsConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.passport_ttl_secs, 3600);
        assert_eq!(config.issuer_id, "test-issuer");
    }

    #[test]
    fn passport_serde_roundtrip() {
        let config = test_config();
        let passport = issue_passport(
            &config,
            "agent-005",
            VALID_HASH,
            &["eu_ai_act".into()],
        );
        let json = serde_json::to_string(&passport).expect("serialize");
        let deser: McpsPassport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.agent_id, "agent-005");
        assert_eq!(deser.composite_hash, VALID_HASH);
        assert_eq!(deser.frameworks_passed, vec!["eu_ai_act"]);
    }
}
