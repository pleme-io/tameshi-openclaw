use crate::core::types::SkillSourceType;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkillAttestationRecord {
    pub skill_name: String,
    pub skill_hash: String,
    pub source_type: SkillSourceType,
    pub permissions: Vec<String>,
    pub attested_at: DateTime<Utc>,
    pub compliance_frameworks: Vec<String>,
}

/// Compute a BLAKE3 attestation hash for a skill.
pub fn compute_skill_hash(name: &str, source_code: &[u8], permissions: &[String]) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(source_code);
    for perm in permissions {
        data.extend_from_slice(perm.as_bytes());
    }
    Blake3Hash::digest(&data).to_prefixed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_hash_deterministic() {
        let h1 = compute_skill_hash("test", b"code", &["net".into()]);
        let h2 = compute_skill_hash("test", b"code", &["net".into()]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn skill_hash_changes_with_content() {
        let h1 = compute_skill_hash("test", b"code1", &[]);
        let h2 = compute_skill_hash("test", b"code2", &[]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn skill_hash_prefixed() {
        let h = compute_skill_hash("test", b"code", &[]);
        assert!(h.starts_with("blake3:"));
    }
}
