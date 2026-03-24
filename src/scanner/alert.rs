use crate::core::types::DriftReport;

/// Alert handler trait for drift notifications.
pub trait AlertHandler: Send + Sync {
    fn alert(&self, report: &DriftReport) -> impl std::future::Future<Output = ()> + Send;
}

/// Log-based alert handler.
pub struct LogAlertHandler;

impl AlertHandler for LogAlertHandler {
    async fn alert(&self, report: &DriftReport) {
        tracing::warn!(
            agent = %report.agent_name,
            layers_changed = report.layers_changed.len(),
            "compliance drift detected"
        );
    }
}
