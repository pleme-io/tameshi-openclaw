use crate::core::types::{GateDecision, NewSkillInput, SkillActivationDecision};
use crate::error::Result;
use crate::skill::gate::SkillCreationGate;

/// Hook called before any new skill is created/activated.
pub async fn on_skill_creation(
    gate: &SkillCreationGate,
    skill: &NewSkillInput,
) -> Result<SkillActivationDecision> {
    let decision = gate.evaluate(skill).await?;

    match &decision.decision {
        GateDecision::Allow => {
            tracing::info!(skill = %decision.skill_name, "skill creation allowed");
        }
        GateDecision::Deny => {
            tracing::warn!(
                skill = %decision.skill_name,
                reasons = ?decision.reasons,
                "skill creation denied"
            );
        }
        GateDecision::Quarantine => {
            tracing::warn!(skill = %decision.skill_name, "skill quarantined for review");
        }
    }

    Ok(decision)
}
