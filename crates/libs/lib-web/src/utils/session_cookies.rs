//! httpOnly cookies carrying the SuperTokens access + refresh tokens.
//!
//! We hand-roll this (no official SuperTokens Rust SDK) so we own the
//! cookie names/scoping directly instead of relying on SDK conventions:
//! - `sAccessToken` — sent with every request, path `/`.
//! - `sRefreshToken` — only ever sent to the refresh endpoint, so a
//!   compromised access-token cookie alone can't be used to mint new ones.

use lib_auth::supertokens::SessionTokens;
use time::OffsetDateTime;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

pub const ACCESS_TOKEN_COOKIE: &str = "sAccessToken";
pub const REFRESH_TOKEN_COOKIE: &str = "sRefreshToken";
pub const REFRESH_TOKEN_PATH: &str = "/api/refresh";

pub fn set_session_cookies(cookies: &Cookies, tokens: &SessionTokens) {
	cookies.add(build_cookie(
		ACCESS_TOKEN_COOKIE,
		tokens.access_token.clone(),
		"/",
		tokens.access_token_expiry_ms,
	));
	cookies.add(build_cookie(
		REFRESH_TOKEN_COOKIE,
		tokens.refresh_token.clone(),
		REFRESH_TOKEN_PATH,
		tokens.refresh_token_expiry_ms,
	));
}

pub fn clear_session_cookies(cookies: &Cookies) {
	let mut access = Cookie::from(ACCESS_TOKEN_COOKIE);
	access.set_path("/");
	cookies.remove(access);

	let mut refresh = Cookie::from(REFRESH_TOKEN_COOKIE);
	refresh.set_path(REFRESH_TOKEN_PATH);
	cookies.remove(refresh);
}

pub fn access_token(cookies: &Cookies) -> Option<String> {
	cookies.get(ACCESS_TOKEN_COOKIE).map(|c| c.value().to_string())
}

pub fn refresh_token(cookies: &Cookies) -> Option<String> {
	cookies.get(REFRESH_TOKEN_COOKIE).map(|c| c.value().to_string())
}

fn build_cookie(name: &'static str, value: String, path: &'static str, expiry_ms: i64) -> Cookie<'static> {
	let mut cookie = Cookie::new(name, value);
	cookie.set_http_only(true);
	cookie.set_path(path);
	cookie.set_same_site(SameSite::Lax);
	// The gateway terminates TLS in front of this service; only mark
	// Secure outside local dev so `cargo run` over http still works.
	cookie.set_secure(!cfg!(debug_assertions));
	if let Ok(expiry) = OffsetDateTime::from_unix_timestamp(expiry_ms / 1000) {
		cookie.set_expires(expiry);
	}
	cookie
}
