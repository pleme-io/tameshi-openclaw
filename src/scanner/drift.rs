use crate::core::types::{DriftReport, LayerDrift};
use chrono::Utc;

/// Compare two sets of layer hashes and detect drift.
pub fn detect_drift(
    agent_name: &str,
    previous: &std::collections::HashMap<String, String>,
    current: &std::collections::HashMap<String, String>,
) -> Option<DriftReport> {
    let mut layers_changed = Vec::new();

    for (layer, current_hash) in current {
        if let Some(prev_hash) = previous.get(layer) {
            if prev_hash != current_hash {
                layers_changed.push(LayerDrift {
                    layer_type: layer.clone(),
                    previous_hash: prev_hash.clone(),
                    current_hash: current_hash.clone(),
                    changed_inputs: vec![],
                });
            }
        } else {
            layers_changed.push(LayerDrift {
                layer_type: layer.clone(),
                previous_hash: String::new(),
                current_hash: current_hash.clone(),
                changed_inputs: vec!["new_layer".into()],
            });
        }
    }

    if layers_changed.is_empty() {
        None
    } else {
        Some(DriftReport {
            agent_name: agent_name.into(),
            layers_changed,
            skills_added: vec![],
            skills_removed: vec![],
            skills_modified: vec![],
            detected_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_drift_returns_none() {
        let mut hashes = HashMap::new();
        hashes.insert("agent_binary".into(), "blake3:abc".into());
        assert!(detect_drift("test", &hashes, &hashes).is_none());
    }

    #[test]
    fn detects_changed_layer() {
        let mut prev = HashMap::new();
        prev.insert("agent_binary".into(), "blake3:old".into());
        let mut curr = HashMap::new();
        curr.insert("agent_binary".into(), "blake3:new".into());
        let report = detect_drift("test", &prev, &curr).unwrap();
        assert_eq!(report.layers_changed.len(), 1);
        assert_eq!(report.layers_changed[0].layer_type, "agent_binary");
    }

    #[test]
    fn detects_new_layer() {
        let prev = HashMap::new();
        let mut curr = HashMap::new();
        curr.insert("agent_skills".into(), "blake3:new".into());
        let report = detect_drift("test", &prev, &curr).unwrap();
        assert_eq!(report.layers_changed.len(), 1);
    }

    #[test]
    fn new_layer_has_changed_inputs_marker() {
        let prev = HashMap::new();
        let mut curr = HashMap::new();
        curr.insert("agent_models".into(), "blake3:first".into());
        let report = detect_drift("my-agent", &prev, &curr).unwrap();
        assert_eq!(report.agent_name, "my-agent");
        assert_eq!(report.layers_changed[0].previous_hash, "");
        assert_eq!(report.layers_changed[0].current_hash, "blake3:first");
        assert_eq!(report.layers_changed[0].changed_inputs, vec!["new_layer"]);
    }

    #[test]
    fn multiple_layers_changed() {
        let mut prev = HashMap::new();
        prev.insert("agent_binary".into(), "hash_a".into());
        prev.insert("agent_config".into(), "hash_b".into());
        let mut curr = HashMap::new();
        curr.insert("agent_binary".into(), "hash_a_new".into());
        curr.insert("agent_config".into(), "hash_b_new".into());
        let report = detect_drift("multi", &prev, &curr).unwrap();
        assert_eq!(report.layers_changed.len(), 2);
        assert!(report.skills_added.is_empty());
        assert!(report.skills_removed.is_empty());
        assert!(report.skills_modified.is_empty());
    }
}
