//! SeaORM entities for local attestation database.
//!
//! These entities store attestation history, gate decisions, and scan results
//! locally. The skill store has its own separate database.

// For now, define the entity structures that will be used with SeaORM.
// The actual sea_orm::entity macros will be added when the migration is set up.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Local record of a gate decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub id: Uuid,
    pub skill_name: String,
    pub decision: String,
    pub attestation_hash: Option<String>,
    pub reasons: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

/// Local record of a compliance scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: Uuid,
    pub agent_name: String,
    pub overall_status: String,
    pub frameworks_assessed: serde_json::Value,
    pub drift_detected: bool,
    pub scanned_at: DateTime<Utc>,
}
