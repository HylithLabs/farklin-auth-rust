//! Active-devices dashboard + remote logout. Everything here reads from
//! SuperTokens core directly (`lib_auth::supertokens`) — no Farklin
//! "sessions" table. The fingerprint shown per device is whatever
//! `handlers_auth` stored in that session's `userDataInDatabase` at
//! signin time (see `lib_web::session_fingerprint::SessionFingerprint`).

use crate::error::{Error, Result};
use axum::routing::{get, post};
use axum::{Json, Router};
use lib_auth::supertokens;
use lib_web::device_label::device_label;
use lib_web::geo_ip::locate;
use lib_web::middleware::mw_auth::CtxW;
use lib_web::session_fingerprint::SessionFingerprint;
use lib_web::Error as WebError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize)]
struct DeviceEntry {
	session_handle: String,
	is_current: bool,
	ip: Option<String>,
	location: Option<String>,
	device_label: Option<String>,
	created_at_ms: i64,
	expires_at_ms: i64,
}

/// `GET /api/sessions` — every device this user is currently signed in
/// on, current one flagged so the UI can label it "This device".
pub async fn api_list_sessions_handler(CtxW(ctx): CtxW) -> Result<Json<Value>> {
	let st_user_id = ctx.st_user_id().ok_or(WebError::CtxMissingSession)?;
	let current_handle = ctx.session_handle();

	let handles = supertokens::list_session_handles(st_user_id).await.map_err(WebError::from)?;

	let mut devices = Vec::with_capacity(handles.len());
	for handle in handles {
		// A handle can go stale between listing and fetching (e.g. it
		// expired in the moment) — skip it rather than fail the whole list.
		let Some(info) = supertokens::get_session_info(&handle).await.map_err(WebError::from)?
		else {
			continue;
		};

		let fingerprint: SessionFingerprint =
			serde_json::from_value(info.user_data_in_database).unwrap_or(SessionFingerprint {
				ip: None,
				visitor_id: None,
				user_agent: None,
			});

		devices.push(DeviceEntry {
			is_current: current_handle == Some(handle.as_str()),
			session_handle: handle,
			location: fingerprint.ip.as_deref().and_then(locate),
			ip: fingerprint.ip,
			device_label: device_label(fingerprint.user_agent.as_deref()),
			created_at_ms: info.time_created_ms,
			expires_at_ms: info.expiry_ms,
		});
	}

	// Current device first, then most-recently-created.
	devices.sort_by(|a, b| {
		b.is_current.cmp(&a.is_current).then(b.created_at_ms.cmp(&a.created_at_ms))
	});

	Ok(Json(json!({ "result": { "devices": devices } })))
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionPayload {
	session_handle: String,
}

/// `POST /api/sessions/revoke` — log out one specific device (not
/// necessarily this one). Only allowed for a handle that's actually the
/// caller's own — checked against the same list `/api/sessions` returns,
/// not trusted blindly from the request body.
pub async fn api_revoke_session_handler(
	CtxW(ctx): CtxW,
	Json(payload): Json<RevokeSessionPayload>,
) -> Result<Json<Value>> {
	let st_user_id = ctx.st_user_id().ok_or(WebError::CtxMissingSession)?;

	let owned_handles = supertokens::list_session_handles(st_user_id).await.map_err(WebError::from)?;
	if !owned_handles.contains(&payload.session_handle) {
		return Err(Error::Web(WebError::SessionNotOwned));
	}

	supertokens::revoke_session(&payload.session_handle).await.map_err(WebError::from)?;

	Ok(Json(json!({ "result": { "revoked": true } })))
}

/// `POST /api/sessions/revoke-others` — "log out everywhere else",
/// keeping the session making this request alive.
pub async fn api_revoke_other_sessions_handler(CtxW(ctx): CtxW) -> Result<Json<Value>> {
	let st_user_id = ctx.st_user_id().ok_or(WebError::CtxMissingSession)?;
	let current_handle = ctx.session_handle();

	let handles = supertokens::list_session_handles(st_user_id).await.map_err(WebError::from)?;
	let others: Vec<String> =
		handles.into_iter().filter(|h| Some(h.as_str()) != current_handle).collect();

	let revoked_count = others.len();
	if !others.is_empty() {
		supertokens::revoke_sessions(&others).await.map_err(WebError::from)?;
	}

	Ok(Json(json!({ "result": { "revoked_count": revoked_count } })))
}

pub fn routes() -> Router {
	Router::new()
		.route("/api/sessions", get(api_list_sessions_handler))
		.route("/api/sessions/revoke", post(api_revoke_session_handler))
		.route("/api/sessions/revoke-others", post(api_revoke_other_sessions_handler))
}
