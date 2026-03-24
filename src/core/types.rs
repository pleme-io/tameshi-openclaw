use async_graphql::{Enum, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Skill activation decision — the core output of the attestation gate.
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct SkillActivationDecision {
    pub decision: GateDecision,
    pub skill_name: String,
    pub attestation_hash: Option<String>,
    pub reasons: Vec<String>,
    pub controls_failed: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Enum, Copy)]
pub enum GateDecision {
    Allow,
    Deny,
    Quarantine,
}

/// Compliance status for an agent.
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct ComplianceStatus {
    pub agent_name: String,
    pub overall_status: OverallStatus,
    pub frameworks_assessed: Vec<FrameworkAssessment>,
    pub last_scan_at: DateTime<Utc>,
    pub skills_attested: u32,
    pub skills_pending: u32,
    pub skills_failed: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Enum, Copy)]
pub enum OverallStatus {
    Compliant,
    NonCompliant,
    Pending,
    Degraded,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct FrameworkAssessment {
    pub framework: String,
    pub status: OverallStatus,
    pub controls_total: u32,
    pub controls_satisfied: u32,
    pub controls_failed: u32,
    pub assessed_at: DateTime<Utc>,
}

/// Drift report from continuous scanning.
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct DriftReport {
    pub agent_name: String,
    pub layers_changed: Vec<LayerDrift>,
    pub skills_added: Vec<String>,
    pub skills_removed: Vec<String>,
    pub skills_modified: Vec<String>,
    pub detected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct LayerDrift {
    pub layer_type: String,
    pub previous_hash: String,
    pub current_hash: String,
    pub changed_inputs: Vec<String>,
}

/// New skill request — input to the attestation gate.
#[derive(Clone, Debug, Serialize, Deserialize, InputObject)]
pub struct NewSkillInput {
    pub name: String,
    pub source_code: String,
    pub permissions: Vec<String>,
    pub source_type: SkillSourceType,
    pub source_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Enum, Copy)]
pub enum SkillSourceType {
    Builtin,
    Store,
    Generated,
    External,
}
