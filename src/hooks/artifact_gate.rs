//! Universal artifact gate — blocks any non-compliant artifact from being
//! used by OpenClaw. This is the top-level enforcement hook that combines
//! all attestation layers into a single pass/fail decision.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tameshi::signature::MasterSignature;

use crate::core::types::GateDecision;

/// Complete artifact attestation status for an OpenClaw deployment.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactGateResult {
    /// Overall gate decision.
    pub decision: GateDecision,
    /// Per-layer attestation results.
    pub layer_results: Vec<LayerGateResult>,
    /// Compliance frameworks that were evaluated.
    pub frameworks_evaluated: Vec<String>,
    /// Compliance frameworks that passed.
    pub frameworks_passed: Vec<String>,
    /// Master signature hash (if fully attested).
    pub master_signature: Option<String>,
    /// When this gate evaluation was performed.
    pub evaluated_at: DateTime<Utc>,
}

/// Result for a single attestation layer.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LayerGateResult {
    /// Layer type name (e.g., "agent_config", "agent_mcp_servers").
    pub layer_type: String,
    /// Whether this layer passed attestation.
    pub passed: bool,
    /// Expected hash for this layer.
    pub expected_hash: Option<String>,
    /// Actual computed hash.
    pub actual_hash: Option<String>,
    /// Reason for failure (if any).
    pub failure_reason: Option<String>,
}

/// Configuration for the universal artifact gate.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactGateConfig {
    /// Required compliance frameworks (all must pass).
    pub required_frameworks: Vec<String>,
    /// Expected layer hashes (layer_type → blake3:hex).
    pub expected_layers: std::collections::HashMap<String, String>,
    /// Whether to require a fully attested master signature.
    pub require_master_signature: bool,
    /// Whether to quarantine (vs. deny) on partial failure.
    pub quarantine_on_partial: bool,
}

impl Default for ArtifactGateConfig {
    fn default() -> Self {
        Self {
            required_frameworks: Vec::new(),
            expected_layers: std::collections::HashMap::new(),
            require_master_signature: true,
            quarantine_on_partial: false,
        }
    }
}

/// Evaluate the universal artifact gate.
///
/// Takes computed layer hashes and compliance results, compares against
/// expected values, and returns a comprehensive gate decision.
#[must_use]
pub fn evaluate_artifact_gate(
    computed_layers: &[(&str, &str)], // (layer_type, computed_hash)
    frameworks_passed: &[String],
    master_signature: Option<&MasterSignature>,
    config: &ArtifactGateConfig,
) -> ArtifactGateResult {
    let mut layer_results = Vec::new();
    let mut all_layers_pass = true;

    // Check each expected layer
    for (layer_type, expected_hash) in &config.expected_layers {
        let actual = computed_layers
            .iter()
            .find(|(lt, _)| *lt == layer_type.as_str())
            .map(|(_, h)| *h);

        let passed = actual.is_some_and(|a| a == expected_hash);
        if !passed {
            all_layers_pass = false;
        }

        layer_results.push(LayerGateResult {
            layer_type: layer_type.clone(),
            passed,
            expected_hash: Some(expected_hash.clone()),
            actual_hash: actual.map(String::from),
            failure_reason: if passed {
                None
            } else if actual.is_none() {
                Some("layer not present in computed hashes".into())
            } else {
                Some("hash mismatch".into())
            },
        });
    }

    // Check compliance frameworks
    let all_frameworks_pass = config.required_frameworks.iter().all(|required| {
        frameworks_passed.iter().any(|p| p == required)
    });

    // Check master signature
    let master_ok = if config.require_master_signature {
        master_signature.is_some_and(|m| m.verify_untested())
    } else {
        true
    };

    let decision = if all_layers_pass && all_frameworks_pass && master_ok {
        GateDecision::Allow
    } else if config.quarantine_on_partial && (all_layers_pass || all_frameworks_pass) {
        GateDecision::Quarantine
    } else {
        GateDecision::Deny
    };

    ArtifactGateResult {
        decision,
        layer_results,
        frameworks_evaluated: config.required_frameworks.clone(),
        frameworks_passed: frameworks_passed.to_vec(),
        master_signature: master_signature.map(|m| m.gating_signature_prefixed()),
        evaluated_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tameshi::hash::Blake3Hash;
    use tameshi::merkle::compute_merkle_root;
    use tameshi::signature::{LayerSignature, LayerType};

    fn make_config(layers: &[(&str, &str)], frameworks: &[&str]) -> ArtifactGateConfig {
        ArtifactGateConfig {
            required_frameworks: frameworks.iter().map(|s| (*s).into()).collect(),
            expected_layers: layers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            require_master_signature: true,
            quarantine_on_partial: false,
        }
    }

    /// Build a valid `MasterSignature` that passes `verify_untested()`.
    fn make_master_signature() -> MasterSignature {
        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        ];
        let root = compute_merkle_root(&layers);
        MasterSignature::new(root, layers, "test")
    }

    #[test]
    fn gate_allows_when_all_pass() {
        let config = make_config(
            &[("agent_config", "blake3:aaa"), ("agent_skills", "blake3:bbb")],
            &["nist_ai_rmf", "eu_ai_act"],
        );
        let computed = vec![
            ("agent_config", "blake3:aaa"),
            ("agent_skills", "blake3:bbb"),
        ];
        let frameworks = vec!["nist_ai_rmf".into(), "eu_ai_act".into()];
        let master = make_master_signature();
        let result = evaluate_artifact_gate(&computed, &frameworks, Some(&master), &config);
        assert_eq!(result.decision, GateDecision::Allow);
        assert!(result.layer_results.iter().all(|l| l.passed));
    }

    #[test]
    fn gate_denies_on_layer_mismatch() {
        let config = make_config(
            &[("agent_config", "blake3:expected")],
            &[],
        );
        let computed = vec![("agent_config", "blake3:wrong")];
        let master = make_master_signature();
        let result = evaluate_artifact_gate(&computed, &[], Some(&master), &config);
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(!result.layer_results[0].passed);
        assert_eq!(
            result.layer_results[0].failure_reason.as_deref(),
            Some("hash mismatch")
        );
    }

    #[test]
    fn gate_denies_on_missing_layer() {
        let config = make_config(
            &[("agent_mcp_servers", "blake3:expected")],
            &[],
        );
        let computed: Vec<(&str, &str)> = vec![];
        let master = make_master_signature();
        let result = evaluate_artifact_gate(&computed, &[], Some(&master), &config);
        assert_eq!(result.decision, GateDecision::Deny);
        assert_eq!(
            result.layer_results[0].failure_reason.as_deref(),
            Some("layer not present in computed hashes")
        );
    }

    #[test]
    fn gate_denies_on_missing_framework() {
        let config = make_config(&[], &["nist_ai_rmf"]);
        let master = make_master_signature();
        let result = evaluate_artifact_gate(&[], &[], Some(&master), &config);
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_denies_on_missing_master_signature() {
        let config = ArtifactGateConfig {
            required_frameworks: vec![],
            expected_layers: HashMap::new(),
            require_master_signature: true,
            quarantine_on_partial: false,
        };
        let result = evaluate_artifact_gate(&[], &[], None, &config);
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_quarantines_on_partial_failure() {
        let mut config = make_config(
            &[("agent_config", "blake3:correct")],
            &["missing_framework"],
        );
        config.quarantine_on_partial = true;

        let computed = vec![("agent_config", "blake3:correct")];
        let master = make_master_signature();
        let result = evaluate_artifact_gate(&computed, &[], Some(&master), &config);
        assert_eq!(result.decision, GateDecision::Quarantine);
    }

    #[test]
    fn gate_allows_without_master_when_not_required() {
        let mut config = ArtifactGateConfig::default();
        config.require_master_signature = false;
        let result = evaluate_artifact_gate(&[], &[], None, &config);
        assert_eq!(result.decision, GateDecision::Allow);
    }

    #[test]
    fn artifact_gate_result_serde_roundtrip() {
        let result = ArtifactGateResult {
            decision: GateDecision::Allow,
            layer_results: vec![LayerGateResult {
                layer_type: "agent_config".into(),
                passed: true,
                expected_hash: Some("blake3:aaa".into()),
                actual_hash: Some("blake3:aaa".into()),
                failure_reason: None,
            }],
            frameworks_evaluated: vec!["nist_ai_rmf".into()],
            frameworks_passed: vec!["nist_ai_rmf".into()],
            master_signature: Some("blake3:master".into()),
            evaluated_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ArtifactGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, result.decision);
        assert_eq!(parsed.layer_results.len(), 1);
    }

    #[test]
    fn default_config_requires_master_signature() {
        let config = ArtifactGateConfig::default();
        assert!(config.require_master_signature);
        assert!(!config.quarantine_on_partial);
        assert!(config.required_frameworks.is_empty());
        assert!(config.expected_layers.is_empty());
    }
}
