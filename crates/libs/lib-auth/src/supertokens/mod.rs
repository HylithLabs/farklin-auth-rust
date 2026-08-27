//! Thin REST client for the SuperTokens core (emailpassword + session
//! recipes). There is no official Rust SDK, so this talks to the core's
//! HTTP API directly, per the Core Driver Interface (CDI) spec:
//! <https://github.com/supertokens/core-driver-interface>
//!
//! Every request needs a `rid` header naming the recipe, and a
//! `cdi-version` header. If the core is started with `API_KEYS` set, an
//! `Authorization: Bearer <key>` header is also required — see
//! [`AuthConfig::SUPERTOKENS_API_KEY`](crate::config::AuthConfig).

mod error;

pub use error::{Error, Result};

use crate::config::auth_config;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::OnceLock;

/// CDI version this client speaks. Bump if the core is upgraded to a
/// version that no longer supports it — check the core's `GET /apiversion`.
const CDI_VERSION: &str = "5.2";

fn http() -> &'static Client {
	static CLIENT: OnceLock<Client> = OnceLock::new();
	CLIENT.get_or_init(Client::new)
}

fn request(method: reqwest::Method, path: &str, rid: &str) -> reqwest::RequestBuilder {
	let cfg = auth_config();
	let url = format!("{}{path}", cfg.SUPERTOKENS_CORE_URL);

	let mut req = http()
		.request(method, url)
		.header("rid", rid)
		.header("cdi-version", CDI_VERSION);

	if let Some(api_key) = &cfg.SUPERTOKENS_API_KEY {
		req = req.header("Authorization", format!("Bearer {api_key}"));
	}

	req
}

// region:    --- EmailPassword Recipe

#[derive(Debug, Clone)]
pub struct SignedUpUser {
	pub user_id: String,
	pub email: String,
}

#[derive(Deserialize)]
struct RecipeUserWire {
	id: String,
	emails: Vec<String>,
}

#[derive(Deserialize)]
struct SignupWire {
	status: String,
	user: Option<RecipeUserWire>,
}

/// `POST /recipe/signup` — creates a new emailpassword user in the core.
/// The core owns password hashing; we never see or store the password.
pub async fn sign_up(email: &str, password: &str) -> Result<SignedUpUser> {
	let res = request(reqwest::Method::POST, "/recipe/signup", "emailpassword")
		.json(&json!({ "email": email, "password": password }))
		.send()
		.await?;

	let wire: SignupWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => {
			let user = wire.user.ok_or(Error::UnexpectedResponse("signup OK with no user"))?;
			Ok(SignedUpUser {
				user_id: user.id,
				email: user.emails.into_iter().next().unwrap_or_default(),
			})
		}
		"EMAIL_ALREADY_EXISTS_ERROR" => Err(Error::EmailAlreadyExists),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

#[derive(Deserialize)]
struct SigninWire {
	status: String,
	user: Option<RecipeUserWire>,
}

/// `POST /recipe/signin` — verifies email+password against the core.
pub async fn sign_in(email: &str, password: &str) -> Result<SignedUpUser> {
	let res = request(reqwest::Method::POST, "/recipe/signin", "emailpassword")
		.json(&json!({ "email": email, "password": password }))
		.send()
		.await?;

	let wire: SigninWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => {
			let user = wire.user.ok_or(Error::UnexpectedResponse("signin OK with no user"))?;
			Ok(SignedUpUser {
				user_id: user.id,
				email: user.emails.into_iter().next().unwrap_or_default(),
			})
		}
		"WRONG_CREDENTIALS_ERROR" => Err(Error::WrongCredentials),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

// endregion: --- EmailPassword Recipe

// region:    --- Session Recipe

#[derive(Debug, Clone, Serialize)]
pub struct SessionTokens {
	pub access_token: String,
	pub access_token_expiry_ms: i64,
	pub refresh_token: String,
	pub refresh_token_expiry_ms: i64,
	pub session_handle: String,
}

#[derive(Deserialize)]
struct CookieInfoWire {
	token: String,
	expiry: i64,
}

#[derive(Deserialize)]
struct SessionWire {
	handle: String,
}

#[derive(Deserialize)]
struct CreateSessionWire {
	status: String,
	session: Option<SessionWire>,
	#[serde(rename = "accessToken")]
	access_token: Option<CookieInfoWire>,
	#[serde(rename = "refreshToken")]
	refresh_token: Option<CookieInfoWire>,
}

/// `POST /recipe/session` — mints access + refresh tokens for `user_id`.
/// Call this right after a successful [`sign_up`] or [`sign_in`].
pub async fn create_session(user_id: &str) -> Result<SessionTokens> {
	let res = request(reqwest::Method::POST, "/recipe/session", "session")
		.json(&json!({
			"userId": user_id,
			"userDataInJWT": {},
			"userDataInDatabase": {},
			"enableAntiCsrf": false,
			"useDynamicSigningKey": true
		}))
		.send()
		.await?;

	let wire: CreateSessionWire = parse(res).await?;
	if wire.status != "OK" {
		return Err(Error::UnexpectedStatus(wire.status));
	}
	let session = wire.session.ok_or(Error::UnexpectedResponse("create session missing session"))?;
	let access = wire.access_token.ok_or(Error::UnexpectedResponse("create session missing accessToken"))?;
	let refresh = wire.refresh_token.ok_or(Error::UnexpectedResponse("create session missing refreshToken"))?;

	Ok(SessionTokens {
		access_token: access.token,
		access_token_expiry_ms: access.expiry,
		refresh_token: refresh.token,
		refresh_token_expiry_ms: refresh.expiry,
		session_handle: session.handle,
	})
}

pub enum VerifyOutcome {
	Valid { user_id: String, session_handle: String },
	/// Access token expired (or close to it) — caller should hit
	/// `/api/refresh` (which calls [`refresh_session`]) and retry.
	TryRefresh,
	Unauthorised,
}

#[derive(Deserialize)]
struct VerifySessionInnerWire {
	#[serde(rename = "userId")]
	user_id: String,
	handle: String,
}

#[derive(Deserialize)]
struct VerifySessionWire {
	status: String,
	session: Option<VerifySessionInnerWire>,
}

/// `POST /recipe/session/verify` — validates an access token.
pub async fn verify_session(access_token: &str) -> Result<VerifyOutcome> {
	let res = request(reqwest::Method::POST, "/recipe/session/verify", "session")
		.json(&json!({
			"accessToken": access_token,
			"enableAntiCsrf": false,
			"doAntiCsrfCheck": false,
			"checkDatabase": false
		}))
		.send()
		.await?;

	let wire: VerifySessionWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => {
			let session = wire.session.ok_or(Error::UnexpectedResponse("verify OK with no session"))?;
			Ok(VerifyOutcome::Valid {
				user_id: session.user_id,
				session_handle: session.handle,
			})
		}
		"TRY_REFRESH_TOKEN" => Ok(VerifyOutcome::TryRefresh),
		"UNAUTHORISED" => Ok(VerifyOutcome::Unauthorised),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

pub enum RefreshOutcome {
	Refreshed(SessionTokens),
	/// A stale/stolen refresh token was replayed. Treat as a hard logout
	/// and force the user to sign in again.
	TokenTheftDetected,
	Unauthorised,
}

#[derive(Deserialize)]
struct RefreshSessionWire {
	status: String,
	session: Option<SessionWire>,
	#[serde(rename = "accessToken")]
	access_token: Option<CookieInfoWire>,
	#[serde(rename = "refreshToken")]
	refresh_token: Option<CookieInfoWire>,
}

/// `POST /recipe/session/refresh` — rotates access + refresh tokens.
pub async fn refresh_session(refresh_token: &str) -> Result<RefreshOutcome> {
	let res = request(reqwest::Method::POST, "/recipe/session/refresh", "session")
		.json(&json!({
			"refreshToken": refresh_token,
			"enableAntiCsrf": false,
			"useDynamicSigningKey": true
		}))
		.send()
		.await?;

	let wire: RefreshSessionWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => {
			let session = wire.session.ok_or(Error::UnexpectedResponse("refresh OK with no session"))?;
			let access = wire.access_token.ok_or(Error::UnexpectedResponse("refresh missing accessToken"))?;
			let refresh = wire.refresh_token.ok_or(Error::UnexpectedResponse("refresh missing refreshToken"))?;
			Ok(RefreshOutcome::Refreshed(SessionTokens {
				access_token: access.token,
				access_token_expiry_ms: access.expiry,
				refresh_token: refresh.token,
				refresh_token_expiry_ms: refresh.expiry,
				session_handle: session.handle,
			}))
		}
		"UNAUTHORISED" => Ok(RefreshOutcome::Unauthorised),
		"TOKEN_THEFT_DETECTED" => Ok(RefreshOutcome::TokenTheftDetected),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

#[derive(Deserialize)]
struct RemoveSessionWire {
	status: String,
}

/// `POST /recipe/session/remove` — revokes one session by handle (logout).
pub async fn revoke_session(session_handle: &str) -> Result<()> {
	let res = request(reqwest::Method::POST, "/recipe/session/remove", "session")
		.json(&json!({ "sessionHandles": [session_handle] }))
		.send()
		.await?;

	let wire: RemoveSessionWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => Ok(()),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

/// `POST /recipe/session/remove` — revokes every session for a user
/// (e.g. "log out everywhere" / risk-triggered kill switch).
pub async fn revoke_all_sessions_for_user(user_id: &str) -> Result<()> {
	let res = request(reqwest::Method::POST, "/recipe/session/remove", "session")
		.json(&json!({ "userId": user_id, "revokeAcrossAllTenants": true }))
		.send()
		.await?;

	let wire: RemoveSessionWire = parse(res).await?;
	match wire.status.as_str() {
		"OK" => Ok(()),
		other => Err(Error::UnexpectedStatus(other.to_string())),
	}
}

// endregion: --- Session Recipe

async fn parse<T: for<'de> Deserialize<'de>>(res: reqwest::Response) -> Result<T> {
	let status = res.status();
	if status != StatusCode::OK {
		let body = res.text().await.unwrap_or_default();
		return Err(Error::CoreHttpError { status: status.as_u16(), body });
	}
	Ok(res.json::<T>().await?)
}
