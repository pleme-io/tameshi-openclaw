use crate::config::OpenClawConfig;
use crate::core::types::{ComplianceStatus, OverallStatus};
use crate::error::Result;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tameshi::hash::Blake3Hash;
use tokio::sync::RwLock;
use tokio::time;

/// Continuous compliance scanning daemon.
pub struct ComplianceScanner {
    config: OpenClawConfig,
    interval: Duration,
    last_hashes: RwLock<HashMap<String, String>>,
}

impl ComplianceScanner {
    pub fn new(config: OpenClawConfig) -> Self {
        let interval = Duration::from_secs(config.scan_interval_secs);
        Self {
            config,
            interval,
            last_hashes: RwLock::new(HashMap::new()),
        }
    }

    /// Hash all files in a directory, returning a combined deterministic hash.
    ///
    /// Files are sorted by path before hashing to ensure determinism.
    /// Returns a sentinel hash if the directory is missing or empty.
    async fn hash_directory(path: &str) -> Result<String> {
        let mut entries = match tokio::fs::read_dir(path).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Blake3Hash::digest(b"empty").to_prefixed());
            }
            Err(e) => return Err(e.into()),
        };

        let mut file_paths = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            if entry_path.is_file() {
                file_paths.push(entry_path);
            }
        }

        // Sort for determinism
        file_paths.sort();

        let mut all_bytes = Vec::new();
        for file_path in &file_paths {
            let name = file_path.display().to_string();
            let contents = tokio::fs::read(file_path).await?;
            all_bytes.extend_from_slice(name.as_bytes());
            all_bytes.extend_from_slice(&contents);
        }

        if all_bytes.is_empty() {
            return Ok(Blake3Hash::digest(b"empty-dir").to_prefixed());
        }

        Ok(Blake3Hash::digest(&all_bytes).to_prefixed())
    }

    /// Hash a single file's contents.
    ///
    /// Returns a sentinel hash if the file does not exist.
    async fn hash_file(path: &str) -> Result<String> {
        match tokio::fs::read(path).await {
            Ok(contents) => Ok(Blake3Hash::digest(&contents).to_prefixed()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Blake3Hash::digest(b"not-found").to_prefixed())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// List skill files and classify by attestation marker.
    ///
    /// Skill files are those ending in `.yaml`, `.json`, or `.toml`.
    /// Status is determined by sibling marker files:
    /// - `skill-name.attested` -> attested
    /// - `skill-name.failed` -> failed
    /// - `skill-name.pending` or no marker -> pending
    async fn classify_skills(skills_dir: &str) -> Result<(u32, u32, u32)> {
        let mut entries = match tokio::fs::read_dir(skills_dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((0, 0, 0));
            }
            Err(e) => return Err(e.into()),
        };

        let mut skill_stems = Vec::new();
        let mut marker_files = HashSet::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                match ext {
                    "yaml" | "json" | "toml" => {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            skill_stems.push(stem.to_string());
                        }
                    }
                    "attested" | "pending" | "failed" => {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            marker_files.insert(format!("{stem}.{ext}"));
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut attested = 0u32;
        let mut pending = 0u32;
        let mut failed = 0u32;

        for skill in &skill_stems {
            if marker_files.contains(&format!("{skill}.failed")) {
                failed += 1;
            } else if marker_files.contains(&format!("{skill}.pending")) {
                pending += 1;
            } else if marker_files.contains(&format!("{skill}.attested")) {
                attested += 1;
            } else {
                // No marker means the skill has not been attested yet
                pending += 1;
            }
        }

        Ok((attested, pending, failed))
    }

    /// Run a single scan cycle.
    ///
    /// Hashes the skills directory and config file, classifies skills by
    /// attestation status, detects drift from the previous scan, and returns
    /// a `ComplianceStatus` reflecting the current state.
    pub async fn scan_once(&self) -> Result<ComplianceStatus> {
        let mut current_hashes = HashMap::new();

        // Hash skills directory
        let skills_hash = Self::hash_directory(&self.config.skills_dir).await?;
        current_hashes.insert("agent_skills".into(), skills_hash);

        // Hash config file
        let config_hash = Self::hash_file(&self.config.config_path).await?;
        current_hashes.insert("agent_config".into(), config_hash);

        // Classify skills by attestation marker
        let (skills_attested, skills_pending, skills_failed) =
            Self::classify_skills(&self.config.skills_dir).await?;

        // Check for drift against previous scan
        let last = self.last_hashes.read().await;
        let drift_detected = !last.is_empty() && *last != current_hashes;
        drop(last);

        // Store current hashes for next comparison
        let mut write = self.last_hashes.write().await;
        *write = current_hashes;
        drop(write);

        // Determine overall status (most severe wins)
        let overall_status = if skills_failed > 0 {
            OverallStatus::NonCompliant
        } else if skills_pending > 0 {
            OverallStatus::Pending
        } else if drift_detected {
            OverallStatus::Degraded
        } else {
            OverallStatus::Compliant
        };

        Ok(ComplianceStatus {
            agent_name: self.config.agent_name.clone(),
            overall_status,
            frameworks_assessed: vec![],
            last_scan_at: chrono::Utc::now(),
            skills_attested,
            skills_pending,
            skills_failed,
        })
    }

    /// Run the scanner daemon loop.
    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            match self.scan_once().await {
                Ok(status) => {
                    tracing::info!(
                        agent = %status.agent_name,
                        status = ?status.overall_status,
                        attested = status.skills_attested,
                        pending = status.skills_pending,
                        failed = status.skills_failed,
                        "compliance scan completed"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "compliance scan failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OpenClawConfig;

    fn test_config(dir: &std::path::Path) -> OpenClawConfig {
        OpenClawConfig {
            agent_name: "test-agent".to_string(),
            skills_dir: dir.join("skills").display().to_string(),
            config_path: dir.join("config.json").display().to_string(),
            store_url: None,
            scan_interval_secs: 60,
            allowed_permissions: vec![],
            authorized_models: vec![],
        }
    }

    #[tokio::test]
    async fn scan_empty_skills_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("skills")).unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.agent_name, "test-agent");
        assert_eq!(status.skills_attested, 0);
        assert_eq!(status.skills_pending, 0);
        assert_eq!(status.skills_failed, 0);
        assert_eq!(status.overall_status, OverallStatus::Compliant);
    }

    #[tokio::test]
    async fn scan_counts_attested_skills() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("code-review.yaml"), "name: code-review").unwrap();
        std::fs::write(skills_dir.join("code-review.attested"), "").unwrap();
        std::fs::write(skills_dir.join("lint.yaml"), "name: lint").unwrap();
        std::fs::write(skills_dir.join("lint.attested"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_attested, 2);
        assert_eq!(status.skills_pending, 0);
        assert_eq!(status.skills_failed, 0);
        assert_eq!(status.overall_status, OverallStatus::Compliant);
    }

    #[tokio::test]
    async fn scan_detects_failed_skills() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("bad-skill.yaml"), "name: bad").unwrap();
        std::fs::write(skills_dir.join("bad-skill.failed"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_failed, 1);
        assert_eq!(status.overall_status, OverallStatus::NonCompliant);
    }

    #[tokio::test]
    async fn scan_pending_without_marker() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("new-skill.yaml"), "name: new").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_pending, 1);
        assert_eq!(status.overall_status, OverallStatus::Pending);
    }

    #[tokio::test]
    async fn scan_detects_drift() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("skill.yaml"), "v1").unwrap();
        std::fs::write(skills_dir.join("skill.attested"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));

        // First scan establishes baseline
        let status1 = scanner.scan_once().await.unwrap();
        assert_eq!(status1.overall_status, OverallStatus::Compliant);

        // Modify a file to cause drift
        std::fs::write(skills_dir.join("skill.yaml"), "v2").unwrap();

        let status2 = scanner.scan_once().await.unwrap();
        assert_eq!(status2.overall_status, OverallStatus::Degraded);
    }

    #[tokio::test]
    async fn scan_missing_skills_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        // Don't create skills dir — should handle gracefully

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_attested, 0);
        assert_eq!(status.skills_pending, 0);
        assert_eq!(status.skills_failed, 0);
    }

    #[tokio::test]
    async fn scan_missing_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        // Don't create config.json — should handle gracefully

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.agent_name, "test-agent");
    }

    #[tokio::test]
    async fn scan_mixed_skill_statuses() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        // One attested, one pending (no marker), one failed
        std::fs::write(skills_dir.join("good.yaml"), "ok").unwrap();
        std::fs::write(skills_dir.join("good.attested"), "").unwrap();
        std::fs::write(skills_dir.join("new.json"), "{}").unwrap();
        std::fs::write(skills_dir.join("broken.toml"), "x").unwrap();
        std::fs::write(skills_dir.join("broken.failed"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_attested, 1);
        assert_eq!(status.skills_pending, 1);
        assert_eq!(status.skills_failed, 1);
        // Failed takes priority over pending
        assert_eq!(status.overall_status, OverallStatus::NonCompliant);
    }

    #[tokio::test]
    async fn scan_no_drift_on_stable_files() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("skill.yaml"), "stable").unwrap();
        std::fs::write(skills_dir.join("skill.attested"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));

        let status1 = scanner.scan_once().await.unwrap();
        assert_eq!(status1.overall_status, OverallStatus::Compliant);

        // Second scan with no changes should still be Compliant
        let status2 = scanner.scan_once().await.unwrap();
        assert_eq!(status2.overall_status, OverallStatus::Compliant);
    }

    #[tokio::test]
    async fn scan_hashes_are_prefixed() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("s.yaml"), "data").unwrap();
        std::fs::write(dir.path().join("config.json"), "cfg").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let _status = scanner.scan_once().await.unwrap();

        let hashes = scanner.last_hashes.read().await;
        for value in hashes.values() {
            assert!(value.starts_with("blake3:"), "hash should be prefixed: {value}");
        }
    }

    #[tokio::test]
    async fn scan_failed_takes_priority_over_pending() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("pending-skill.yaml"), "p").unwrap();
        std::fs::write(skills_dir.join("failed-skill.yaml"), "f").unwrap();
        std::fs::write(skills_dir.join("failed-skill.failed"), "").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();

        let scanner = ComplianceScanner::new(test_config(dir.path()));
        let status = scanner.scan_once().await.unwrap();

        assert_eq!(status.skills_pending, 1);
        assert_eq!(status.skills_failed, 1);
        // NonCompliant takes priority over Pending
        assert_eq!(status.overall_status, OverallStatus::NonCompliant);
    }
}
