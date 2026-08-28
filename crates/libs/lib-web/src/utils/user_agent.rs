use axum::http::HeaderMap;

/// Raw `User-Agent` header, stored per-session for the active-devices
/// dashboard to label later (see `crate::device_label`) — kept raw here,
/// not parsed at capture time, so the label format can change later
/// without needing to touch anything already stored.
pub fn user_agent(headers: &HeaderMap) -> Option<String> {
	headers
		.get("user-agent")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.to_string())
}
