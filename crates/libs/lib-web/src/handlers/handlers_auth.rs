use crate::error::{Error, Result};
use crate::utils::client_ip::client_ip;
use crate::utils::session_cookies::{self, clear_session_cookies, set_session_cookies};
use crate::utils::user_agent::user_agent;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use lib_auth::risk::{self, Outcome as RiskOutcome};
use lib_auth::supertokens::{self, RefreshOutcome, SessionTokens, VerifyOutcome};
use lib_core::ctx::Ctx;
use lib_core::model::user::{UserBmc, UserForAuth, UserForCreate};
use lib_core::model::ModelManager;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_cookies::Cookies;
use tracing::{debug, warn};
use validator::Validate;

// region:    --- Signup

#[derive(Debug, Deserialize, Validate)]
pub struct SignupPayload {
	#[validate(email)]
	email: String,
	#[validate(length(min = 8, message = "password must be at least 8 characters"))]
	password: String,
	/// FingerprintJS `visitorId`. Optional so signup still works for a
	/// client that hasn't loaded it (or has it blocked) — it just means
	/// there's no login-risk baseline to compare their *next* signin
	/// against until one is captured.
	visitor_id: Option<String>,
}

pub async fn api_signup_handler(
	State(mm): State<ModelManager>,
	headers: HeaderMap,
	cookies: Cookies,
	Json(payload): Json<SignupPayload>,
) -> Result<Json<Value>> {
	debug!("{:<12} - api_signup_handler", "HANDLER");
	payload.validate().map_err(|ex| Error::ValidationFail(ex.to_string()))?;

	let signed_up = supertokens::sign_up(&payload.email, &payload.password).await?;
	let current_ip = client_ip(&headers);

	let root_ctx = Ctx::root_ctx();
	UserBmc::create(
		&root_ctx,
		&mm,
		UserForCreate {
			st_user_id: signed_up.user_id.clone(),
			email: signed_up.email.clone(),
			// Nothing to check risk against on a first-ever login — just
			// record it as the baseline the *next* signin gets compared to.
			last_ip: current_ip.clone(),
			last_visitor_id: payload.visitor_id.clone(),
		},
	)
	.await?;

	let fingerprint = json!({
		"ip": current_ip,
		"visitor_id": payload.visitor_id,
		"user_agent": user_agent(&headers),
	});
	let tokens = supertokens::create_session(&signed_up.user_id, fingerprint).await?;
	set_session_cookies(&cookies, &tokens);

	Ok(Json(json!({ "result": { "success": true, "email": signed_up.email } })))
}

// endregion: --- Signup

// region:    --- Signin

#[derive(Debug, Deserialize)]
pub struct SigninPayload {
	email: String,
	password: String,
	visitor_id: Option<String>,
}

pub async fn api_signin_handler(
	State(mm): State<ModelManager>,
	headers: HeaderMap,
	cookies: Cookies,
	Json(payload): Json<SigninPayload>,
) -> Result<Json<Value>> {
	debug!("{:<12} - api_signin_handler", "HANDLER");

	let signed_in = supertokens::sign_in(&payload.email, &payload.password).await?;
	let current_ip = client_ip(&headers);
	let current_visitor_id = payload.visitor_id;

	let root_ctx = Ctx::root_ctx();
	// The core is the source of truth. If this is the first time we've
	// seen this st_user_id locally (e.g. account existed before this
	// mirror table did), backfill it now instead of failing the signin —
	// and same as signup, nothing to check risk against yet.
	let existing: Option<UserForAuth> =
		UserBmc::first_by_st_user_id(&root_ctx, &mm, &signed_in.user_id).await?;

	let user_id = match existing {
		None => {
			UserBmc::create(
				&root_ctx,
				&mm,
				UserForCreate {
					st_user_id: signed_in.user_id.clone(),
					email: signed_in.email.clone(),
					last_ip: current_ip.clone(),
					last_visitor_id: current_visitor_id.clone(),
				},
			)
			.await?
		}
		Some(user) => {
			// A baseline field being `None` means we never captured one
			// (e.g. an older row, or a signup with fingerprinting
			// blocked) — "unknown" is not "changed", so that only counts
			// as a mismatch when we have a real prior value to compare.
			let device_changed = matches!(
				(&user.last_visitor_id, &current_visitor_id),
				(Some(prev), Some(curr)) if prev != curr
			);
			let ip_changed = matches!(
				(&user.last_ip, &current_ip),
				(Some(prev), Some(curr)) if prev != curr
			);

			match risk::evaluate(device_changed, ip_changed).await? {
				RiskOutcome::Block { reason } => {
					warn!(
						user_id = user.id,
						reason, "signin blocked by login-risk check"
					);
					return Err(Error::LoginBlockedRisk);
				}
				RiskOutcome::Flag { reason } => {
					warn!(user_id = user.id, reason, "signin flagged by login-risk check");
				}
				RiskOutcome::Allow => {}
			}

			// Only reached past a Block — never overwrite the baseline
			// with a fingerprint the risk check just rejected.
			UserBmc::update_login_fingerprint(
				&root_ctx,
				&mm,
				user.id,
				current_ip.clone(),
				current_visitor_id.clone(),
			)
			.await?;

			user.id
		}
	};

	let fingerprint = json!({
		"ip": current_ip,
		"visitor_id": current_visitor_id,
		"user_agent": user_agent(&headers),
	});
	let tokens = supertokens::create_session(&signed_in.user_id, fingerprint).await?;
	set_session_cookies(&cookies, &tokens);

	debug!("{:<12} - signin ok for local user_id={user_id}", "HANDLER");
	Ok(Json(json!({ "result": { "success": true, "email": signed_in.email } })))
}

// endregion: --- Signin

// region:    --- Refresh

/// Half of `REFRESH_TOKEN_VALIDITY` (docker-compose.dev.yml — 30 days).
/// SuperTokens has no API to extend a refresh token's expiry in place —
/// confirmed against its own CDI spec: `/recipe/session/regenerate`
/// only touches the access token's JWT payload, not the refresh token's
/// deadline, and a plain refresh rotates the token without moving that
/// deadline forward. So genuine "stay logged in forever while active"
/// means swapping in a brand-new session once the current one is more
/// than half spent — reusing `create_session`/`revoke_session` (already
/// built for signin/logoff), not a new SuperTokens API call.
const SLIDING_WINDOW_THRESHOLD_MS: i64 = 15 * 24 * 60 * 60 * 1000;

pub async fn api_refresh_handler(cookies: Cookies) -> Result<Json<Value>> {
	debug!("{:<12} - api_refresh_handler", "HANDLER");

	let refresh_token = session_cookies::refresh_token(&cookies)
		.ok_or(Error::RefreshTokenMissing)?;

	match supertokens::refresh_session(&refresh_token).await? {
		RefreshOutcome::Refreshed(tokens) => {
			let tokens = slide_window_if_needed(tokens).await?;
			set_session_cookies(&cookies, &tokens);
			Ok(Json(json!({ "result": { "refreshed": true } })))
		}
		RefreshOutcome::TokenTheftDetected => {
			clear_session_cookies(&cookies);
			Err(Error::SessionTokenTheftDetected)
		}
		RefreshOutcome::Unauthorised => {
			clear_session_cookies(&cookies);
			Err(Error::RefreshFail)
		}
	}
}

/// If less than half the refresh window remains, replace the session
/// with a brand-new one — same fingerprint data carried forward — instead
/// of handing back the just-rotated tokens as-is.
async fn slide_window_if_needed(tokens: SessionTokens) -> Result<SessionTokens> {
	let now_ms = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
	let remaining_ms = tokens.refresh_token_expiry_ms - now_ms;

	if remaining_ms > SLIDING_WINDOW_THRESHOLD_MS {
		return Ok(tokens);
	}

	let fingerprint = supertokens::get_session_info(&tokens.session_handle)
		.await?
		.map(|info| info.user_data_in_database)
		.unwrap_or(Value::Null);

	let fresh = supertokens::create_session(&tokens.user_id, fingerprint).await?;
	// Best-effort: the old session is being replaced either way — if this
	// fails it just lingers until its (already near) expiry.
	let _ = supertokens::revoke_session(&tokens.session_handle).await;

	Ok(fresh)
}

// endregion: --- Refresh

// region:    --- Logoff

#[derive(Debug, Deserialize)]
pub struct LogoffPayload {
	logoff: bool,
}

pub async fn api_logoff_handler(
	cookies: Cookies,
	Json(payload): Json<LogoffPayload>,
) -> Result<Json<Value>> {
	debug!("{:<12} - api_logoff_handler", "HANDLER");
	let should_logoff = payload.logoff;

	if should_logoff {
		if let Some(access_token) = session_cookies::access_token(&cookies) {
			if let Ok(VerifyOutcome::Valid { session_handle, .. }) =
				supertokens::verify_session(&access_token).await
			{
				// Best-effort: an already-dead session just means there's
				// nothing left to revoke.
				let _ = supertokens::revoke_session(&session_handle).await;
			}
		}
		clear_session_cookies(&cookies);
	}

	Ok(Json(json!({ "result": { "logged_off": should_logoff } })))
}

// endregion: --- Logoff
