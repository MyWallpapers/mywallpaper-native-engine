//! Nonfatal observations use stderr; stdout remains the exact process-v2 wire.
pub(crate) fn emit(
    severity: &str,
    code: &str,
    operation: &str,
    message: &str,
    target_pid: Option<u32>,
) {
    // A diagnostic is bounded independently of add-on settings/message payloads.
    let message: String = message.chars().take(4096).collect();
    eprintln!(
        "{}",
        serde_json::json!({
            "source": "mywallpaper-native-engine", "schemaVersion": 1,
            "severity": severity, "code": code, "operation": operation,
            "message": message, "targetPid": target_pid
        })
    );
}
