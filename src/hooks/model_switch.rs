use crate::config::OpenClawConfig;

/// Verify that a model switch is to an authorized provider.
pub fn verify_model_switch(config: &OpenClawConfig, provider: &str, model_id: &str) -> bool {
    config
        .authorized_models
        .iter()
        .any(|m| m.provider == provider && m.model_id == model_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthorizedModel;

    #[test]
    fn allows_authorized_model() {
        let config = OpenClawConfig {
            agent_name: "test".into(),
            skills_dir: "/tmp".into(),
            config_path: "/tmp/c.json".into(),
            store_url: None,
            scan_interval_secs: 300,
            allowed_permissions: vec![],
            authorized_models: vec![AuthorizedModel {
                provider: "anthropic".into(),
                model_id: "claude-opus-4-6".into(),
            }],
        };
        assert!(verify_model_switch(&config, "anthropic", "claude-opus-4-6"));
    }

    #[test]
    fn denies_unauthorized_model() {
        let config = OpenClawConfig {
            agent_name: "test".into(),
            skills_dir: "/tmp".into(),
            config_path: "/tmp/c.json".into(),
            store_url: None,
            scan_interval_secs: 300,
            allowed_permissions: vec![],
            authorized_models: vec![],
        };
        assert!(!verify_model_switch(&config, "openai", "gpt-5"));
    }
}
