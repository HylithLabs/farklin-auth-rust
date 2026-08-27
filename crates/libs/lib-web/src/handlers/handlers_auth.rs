use crate::error::{Error, Result};
use crate::utils::session_cookies::{self, clear_session_cookies, set_session_cookies};
use axum::extract::State;
use axum::Json;
use lib_auth::supertokens::{self, RefreshOutcome, VerifyOutcome};
use lib_core::ctx::Ctx;
use lib_core::model::user::{UserBmc, UserForAuth, UserForCreate};
use lib_core::model::ModelManager;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_cookies::Cookies;
use tracing::debug;
use validator::Validate;

// region:    --- Signup

#[derive(Debug, Deserialize, Validate)]
pub struct SignupPayload {
	#[validate(email)]
	email: String,
	#[validate(length(min = 8, message = "password must be at least 8 characters"))]
	password: String,
}

pub async fn api_signup_handler(
	State(mm): State<ModelManager>,
	cookies: Cookies,
	Json(payload): Json<SignupPayload>,
) -> Result<Json<Value>> {
	debug!("{:<12} - api_signup_handler", "HANDLER");
	payload.validate().map_err(|ex| Error::ValidationFail(ex.to_string()))?;

	let signed_up = supertokens::sign_up(&payload.email, &payload.password).await?;

	let root_ctx = Ctx::root_ctx();
	UserBmc::create(
		&root_ctx,
		&mm,
		UserForCreate {
			st_user_id: signed_up.user_id.clone(),
			email: signed_up.email.clone(),
		},
	)
	.await?;

	let tokens = supertokens::create_session(&signed_up.user_id).await?;
	set_session_cookies(&cookies, &tokens);

	Ok(Json(json!({ "result": { "success": true, "email": signed_up.email } })))
}

// endregion: --- Signup

// region:    --- Signin

#[derive(Debug, Deserialize)]
pub struct SigninPayload {
	email: String,
	password: String,
}

pub async fn api_signin_handler(
	State(mm): State<ModelManager>,
	cookies: Cookies,
	Json(payload): Json<SigninPayload>,
) -> Result<Json<Value>> {
	debug!("{:<12} - api_signin_handler", "HANDLER");

	let signed_in = supertokens::sign_in(&payload.email, &payload.password).await?;

	let root_ctx = Ctx::root_ctx();
	// The core is the source of truth. If this is the first time we've
	// seen this st_user_id locally (e.g. account existed before this
	// mirror table did), backfill it now instead of failing the signin.
	let existing: Option<UserForAuth> =
		UserBmc::first_by_st_user_id(&root_ctx, &mm, &signed_in.user_id).await?;
	if existing.is_none() {
		UserBmc::create(
			&root_ctx,
			&mm,
			UserForCreate {
				st_user_id: signed_in.user_id.clone(),
				email: signed_in.email.clone(),
			},
		)
		.await?;
	}

	let tokens = supertokens::create_session(&signed_in.user_id).await?;
	set_session_cookies(&cookies, &tokens);

	Ok(Json(json!({ "result": { "success": true, "email": signed_in.email } })))
}

// endregion: --- Signin

// region:    --- Refresh

pub async fn api_refresh_handler(cookies: Cookies) -> Result<Json<Value>> {
	debug!("{:<12} - api_refresh_handler", "HANDLER");

	let refresh_token = session_cookies::refresh_token(&cookies)
		.ok_or(Error::RefreshTokenMissing)?;

	match supertokens::refresh_session(&refresh_token).await? {
		RefreshOutcome::Refreshed(tokens) => {
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
