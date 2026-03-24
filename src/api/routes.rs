use axum::{Json, extract::State, routing::get};
use crate::core::types::ComplianceStatus;
use std::sync::Arc;

pub struct AppState {
    pub agent_name: String,
}

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn status(State(state): State<Arc<AppState>>) -> Json<ComplianceStatus> {
    Json(ComplianceStatus {
        agent_name: state.agent_name.clone(),
        overall_status: crate::core::types::OverallStatus::Pending,
        frameworks_assessed: vec![],
        last_scan_at: chrono::Utc::now(),
        skills_attested: 0,
        skills_pending: 0,
        skills_failed: 0,
    })
}
