use async_graphql::SimpleObject;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, JsonSchema)]
pub struct AuthorizedModel {
    pub provider: String,
    pub model_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, JsonSchema)]
pub struct OpenClawConfig {
    pub agent_name: String,
    pub skills_dir: String,
    pub config_path: String,
    pub store_url: Option<String>,
    pub scan_interval_secs: u64,
    pub allowed_permissions: Vec<String>,
    #[serde(default)]
    pub authorized_models: Vec<AuthorizedModel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serde_roundtrip() {
        let config = OpenClawConfig {
            agent_name: "test-agent".to_string(),
            skills_dir: "/opt/skills".to_string(),
            config_path: "/opt/config.json".to_string(),
            store_url: Some("https://store.example.com".to_string()),
            scan_interval_secs: 60,
            allowed_permissions: vec!["read".into(), "write".into()],
            authorized_models: vec![],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OpenClawConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_name, config.agent_name);
        assert_eq!(deserialized.skills_dir, config.skills_dir);
        assert_eq!(deserialized.config_path, config.config_path);
        assert_eq!(deserialized.store_url, config.store_url);
        assert_eq!(deserialized.scan_interval_secs, config.scan_interval_secs);
        assert_eq!(deserialized.allowed_permissions, config.allowed_permissions);
    }

    #[test]
    fn config_with_authorized_models() {
        let config = OpenClawConfig {
            agent_name: "agent-1".to_string(),
            skills_dir: "/skills".to_string(),
            config_path: "/config.json".to_string(),
            store_url: None,
            scan_interval_secs: 300,
            allowed_permissions: vec![],
            authorized_models: vec![
                AuthorizedModel {
                    provider: "openai".to_string(),
                    model_id: "gpt-4o".to_string(),
                },
                AuthorizedModel {
                    provider: "anthropic".to_string(),
                    model_id: "claude-opus-4-6".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OpenClawConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.authorized_models.len(), 2);
        assert_eq!(deserialized.authorized_models[0].provider, "openai");
        assert_eq!(deserialized.authorized_models[1].model_id, "claude-opus-4-6");
    }

    #[test]
    fn config_schema_generation() {
        let schema = schemars::schema_for!(OpenClawConfig);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("OpenClawConfig"));
        assert!(json.contains("agent_name"));
        assert!(json.contains("skills_dir"));
        assert!(json.contains("authorized_models"));
    }
}
