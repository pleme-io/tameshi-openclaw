use crate::core::types::{GateDecision, SkillActivationDecision};
use crate::error::Result;
use crate::skill::store_client::StoreClient;
use chrono::Utc;

/// Hook called before a skill from the store is activated.
pub async fn on_skill_activation(
    store: &StoreClient,
    skill_id: &str,
    skill_name: &str,
) -> Result<SkillActivationDecision> {
    let valid = store.verify_skill(skill_id).await?;

    if valid {
        Ok(SkillActivationDecision {
            decision: GateDecision::Allow,
            skill_name: skill_name.into(),
            attestation_hash: Some(skill_id.into()),
            reasons: vec!["store attestation verified".into()],
            controls_failed: vec![],
            decided_at: Utc::now(),
        })
    } else {
        Ok(SkillActivationDecision {
            decision: GateDecision::Deny,
            skill_name: skill_name.into(),
            attestation_hash: None,
            reasons: vec!["store attestation invalid or revoked".into()],
            controls_failed: vec!["store_attestation".into()],
            decided_at: Utc::now(),
        })
    }
}
