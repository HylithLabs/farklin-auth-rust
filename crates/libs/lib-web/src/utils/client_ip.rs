use axum::http::HeaderMap;

/// The real browser IP, as forwarded by farklin-gateway-ts (the only hop
/// between the browser and this service — see
/// farklin-gateway-ts/src/routes/auth.ts's `rewriteRequestHeaders`). Not a
/// general-purpose X-Forwarded-For chain parser: single hop, single value,
/// trusted because nothing but the gateway calls this service directly.
///
/// `None` if the header is missing (e.g. hitting this service directly in
/// dev, bypassing the gateway) — callers should treat that as "unknown",
/// not as a mismatch.
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
	headers
		.get("x-forwarded-for")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty())
}
