use crate::config::OpenClawConfig;
use crate::core::types::{GateDecision, NewSkillInput, SkillActivationDecision};
use crate::error::Result;
use chrono::Utc;
use tameshi::hash::Blake3Hash;

/// Gate that evaluates new skills before they can be activated.
pub struct SkillCreationGate {
    config: OpenClawConfig,
}

impl SkillCreationGate {
    pub fn new(config: OpenClawConfig) -> Self {
        Self { config }
    }

    /// Evaluate whether a new skill should be activated.
    pub async fn evaluate(&self, skill: &NewSkillInput) -> Result<SkillActivationDecision> {
        // 1. Hash the skill source code
        let skill_hash = Blake3Hash::digest(skill.source_code.as_bytes());

        // 2. Check permission boundaries
        let mut denied_permissions = Vec::new();
        for perm in &skill.permissions {
            if !self.config.allowed_permissions.contains(perm) {
                denied_permissions.push(format!("permission '{perm}' not in allowed list"));
            }
        }

        if !denied_permissions.is_empty() {
            return Ok(SkillActivationDecision {
                decision: GateDecision::Deny,
                skill_name: skill.name.clone(),
                attestation_hash: None,
                reasons: denied_permissions.clone(),
                controls_failed: denied_permissions,
                decided_at: Utc::now(),
            });
        }

        // 3. Skill passes basic checks — attest it
        Ok(SkillActivationDecision {
            decision: GateDecision::Allow,
            skill_name: skill.name.clone(),
            attestation_hash: Some(skill_hash.to_prefixed()),
            reasons: vec!["all checks passed".into()],
            controls_failed: vec![],
            decided_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OpenClawConfig;
    use crate::core::types::SkillSourceType;

    fn test_config() -> OpenClawConfig {
        OpenClawConfig {
            agent_name: "test-agent".into(),
            skills_dir: "/tmp/skills".into(),
            config_path: "/tmp/config.json".into(),
            store_url: None,
            scan_interval_secs: 300,
            allowed_permissions: vec!["network".into(), "filesystem_read".into()],
            authorized_models: vec![],
        }
    }

    #[tokio::test]
    async fn gate_allows_valid_skill() {
        let gate = SkillCreationGate::new(test_config());
        let skill = NewSkillInput {
            name: "search".into(),
            source_code: "def search(): pass".into(),
            permissions: vec!["network".into()],
            source_type: SkillSourceType::Builtin,
            source_ref: None,
        };
        let decision = gate.evaluate(&skill).await.unwrap();
        assert_eq!(decision.decision, GateDecision::Allow);
        assert!(decision.attestation_hash.is_some());
    }

    #[tokio::test]
    async fn gate_denies_unauthorized_permission() {
        let gate = SkillCreationGate::new(test_config());
        let skill = NewSkillInput {
            name: "dangerous".into(),
            source_code: "import os; os.system('rm -rf /')".into(),
            permissions: vec!["shell".into()],
            source_type: SkillSourceType::Generated,
            source_ref: None,
        };
        let decision = gate.evaluate(&skill).await.unwrap();
        assert_eq!(decision.decision, GateDecision::Deny);
        assert!(!decision.reasons.is_empty());
    }

    #[tokio::test]
    async fn gate_hash_is_deterministic() {
        let gate = SkillCreationGate::new(test_config());
        let skill = NewSkillInput {
            name: "test".into(),
            source_code: "def test(): pass".into(),
            permissions: vec!["network".into()],
            source_type: SkillSourceType::Builtin,
            source_ref: None,
        };
        let d1 = gate.evaluate(&skill).await.unwrap();
        let d2 = gate.evaluate(&skill).await.unwrap();
        assert_eq!(d1.attestation_hash, d2.attestation_hash);
    }
}
