//! SeaORM entities for local attestation database.
//!
//! These entities store attestation history, gate decisions, and scan results
//! locally. The skill store has its own separate database.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::SkillActivationDecision;
use crate::entities;

/// Local record of a gate decision.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GateDecisionRecord {
    pub id: Uuid,
    pub skill_name: String,
    pub decision: String,
    pub attestation_hash: Option<String>,
    pub reasons: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

/// Local record of a compliance scan.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ScanRecord {
    pub id: Uuid,
    pub agent_name: String,
    pub overall_status: String,
    pub frameworks_assessed: serde_json::Value,
    pub drift_detected: bool,
    pub scanned_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Conversions: core types -> wrapper records
// ---------------------------------------------------------------------------

/// Convert a `SkillActivationDecision` into a `GateDecisionRecord`.
///
/// The `decision` enum is serialized as a JSON string for storage.
impl From<SkillActivationDecision> for GateDecisionRecord {
    fn from(d: SkillActivationDecision) -> Self {
        Self {
            id: Uuid::new_v4(),
            skill_name: d.skill_name,
            decision: serde_json::to_string(&d.decision).unwrap_or_default(),
            attestation_hash: d.attestation_hash,
            reasons: d.reasons,
            decided_at: d.decided_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions: SeaORM entity Models <-> core types
// ---------------------------------------------------------------------------

/// Convert a SeaORM gate decision `Model` into a `GateDecisionRecord`.
impl From<entities::gate_decision::Model> for GateDecisionRecord {
    fn from(m: entities::gate_decision::Model) -> Self {
        let id = m.id.parse::<Uuid>().unwrap_or_else(|_| Uuid::nil());
        let decided_at = m
            .decided_at
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now());

        Self {
            id,
            skill_name: m.agent_name,
            decision: m.decision,
            attestation_hash: m.computed_hash,
            reasons: vec![m.reason],
            decided_at,
        }
    }
}

/// Convert a `GateDecisionRecord` into a SeaORM gate decision `Model`.
///
/// The `gate_type` defaults to `"skill_activation"`. Reasons are joined with
/// semicolons into a single string.
impl From<GateDecisionRecord> for entities::gate_decision::Model {
    fn from(r: GateDecisionRecord) -> Self {
        Self {
            id: r.id.to_string(),
            agent_name: r.skill_name,
            decision: r.decision,
            gate_type: "skill_activation".to_string(),
            reason: r.reasons.join("; "),
            computed_hash: r.attestation_hash,
            decided_at: r.decided_at.to_rfc3339(),
        }
    }
}

/// Convert a `SkillActivationDecision` directly into a SeaORM gate decision `Model`.
impl From<SkillActivationDecision> for entities::gate_decision::Model {
    fn from(d: SkillActivationDecision) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent_name: d.skill_name,
            decision: serde_json::to_string(&d.decision).unwrap_or_default(),
            gate_type: "skill_activation".to_string(),
            reason: d.reasons.join("; "),
            computed_hash: d.attestation_hash,
            decided_at: d.decided_at.to_rfc3339(),
        }
    }
}

/// Convert a SeaORM scan record `Model` into a `ScanRecord`.
impl From<entities::scan_record::Model> for ScanRecord {
    fn from(m: entities::scan_record::Model) -> Self {
        let id = m.id.parse::<Uuid>().unwrap_or_else(|_| Uuid::nil());
        let scanned_at = m
            .scanned_at
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now());

        Self {
            id,
            agent_name: m.agent_name,
            overall_status: m.compliance_status,
            frameworks_assessed: serde_json::json!({ "layers_hashed": m.layers_hashed }),
            drift_detected: m.drift_detected != 0,
            scanned_at,
        }
    }
}

/// Convert a `ScanRecord` into a SeaORM scan record `Model`.
impl From<ScanRecord> for entities::scan_record::Model {
    fn from(r: ScanRecord) -> Self {
        Self {
            id: r.id.to_string(),
            agent_name: r.agent_name,
            layers_hashed: r
                .frameworks_assessed
                .get("layers_hashed")
                .and_then(serde_json::Value::as_i64)
                .map_or(0, |v| i32::try_from(v).unwrap_or(0)),
            drift_detected: i32::from(r.drift_detected),
            compliance_status: r.overall_status,
            scanned_at: r.scanned_at.to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::GateDecision;

    #[test]
    fn gate_decision_record_serializes() {
        let record = GateDecisionRecord {
            id: Uuid::new_v4(),
            skill_name: "test-skill".into(),
            decision: "allow".into(),
            attestation_hash: Some("blake3:abc".into()),
            reasons: vec!["all clear".into()],
            decided_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("test-skill"));
    }

    #[test]
    fn scan_record_serializes() {
        let record = ScanRecord {
            id: Uuid::new_v4(),
            agent_name: "agent-1".into(),
            overall_status: "compliant".into(),
            frameworks_assessed: serde_json::json!({"nist": true}),
            drift_detected: false,
            scanned_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("agent-1"));
    }

    #[test]
    fn skill_activation_to_gate_decision_record() {
        let decision = SkillActivationDecision {
            decision: GateDecision::Allow,
            skill_name: "my-skill".into(),
            attestation_hash: Some("blake3:xyz".into()),
            reasons: vec!["passed".into()],
            controls_failed: vec![],
            decided_at: Utc::now(),
        };

        let record: GateDecisionRecord = decision.into();
        assert_eq!(record.skill_name, "my-skill");
        assert!(record.decision.contains("Allow"));
    }

    #[test]
    fn seaorm_gate_decision_model_round_trip() {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let record = GateDecisionRecord {
            id,
            skill_name: "skill-a".into(),
            decision: "deny".into(),
            attestation_hash: None,
            reasons: vec!["reason1".into(), "reason2".into()],
            decided_at: now,
        };

        let model: entities::gate_decision::Model = record.into();
        assert_eq!(model.id, id.to_string());
        assert_eq!(model.agent_name, "skill-a");
        assert_eq!(model.decision, "deny");
        assert!(model.reason.contains("reason1"));
        assert!(model.reason.contains("reason2"));

        let restored: GateDecisionRecord = model.into();
        assert_eq!(restored.id, id);
        assert_eq!(restored.skill_name, "skill-a");
    }

    #[test]
    fn seaorm_scan_record_model_round_trip() {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let record = ScanRecord {
            id,
            agent_name: "agent-x".into(),
            overall_status: "compliant".into(),
            frameworks_assessed: serde_json::json!({"layers_hashed": 5}),
            drift_detected: true,
            scanned_at: now,
        };

        let model: entities::scan_record::Model = record.into();
        assert_eq!(model.id, id.to_string());
        assert_eq!(model.agent_name, "agent-x");
        assert_eq!(model.layers_hashed, 5);
        assert_eq!(model.drift_detected, 1);
        assert_eq!(model.compliance_status, "compliant");

        let restored: ScanRecord = model.into();
        assert_eq!(restored.id, id);
        assert_eq!(restored.agent_name, "agent-x");
        assert!(restored.drift_detected);
    }

    #[test]
    fn skill_activation_to_seaorm_model() {
        let decision = SkillActivationDecision {
            decision: GateDecision::Deny,
            skill_name: "risky-skill".into(),
            attestation_hash: Some("hash123".into()),
            reasons: vec!["failed check".into()],
            controls_failed: vec!["AC-1".into()],
            decided_at: Utc::now(),
        };

        let model: entities::gate_decision::Model = decision.into();
        assert_eq!(model.agent_name, "risky-skill");
        assert!(model.decision.contains("Deny"));
        assert_eq!(model.gate_type, "skill_activation");
        assert_eq!(model.computed_hash, Some("hash123".into()));
    }
}
