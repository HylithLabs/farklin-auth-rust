use crate::error::{Error, Result};
use crate::utils::session_cookies::{self, clear_session_cookies};
use axum::body::Body;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use lib_auth::supertokens::{self, VerifyOutcome};
use lib_core::ctx::Ctx;
use lib_core::model::user::{UserBmc, UserForAuth};
use lib_core::model::ModelManager;
use serde::Serialize;
use tower_cookies::Cookies;
use tracing::debug;

pub async fn mw_ctx_require(
	ctx: Result<CtxW>,
	req: Request<Body>,
	next: Next,
) -> Result<Response> {
	debug!("{:<12} - mw_ctx_require - {ctx:?}", "MIDDLEWARE");

	ctx?;

	Ok(next.run(req).await)
}

// IMPORTANT: This resolver must never fail, but rather capture the potential Auth error and put in in the
//            request extension as CtxExtResult.
//            This way it won't prevent downstream middleware to be executed, and will still capture the error
//            for the appropriate middleware (.e.g., mw_ctx_require which forces successful auth) or handler
//            to get the appropriate information.
pub async fn mw_ctx_resolver(
	State(mm): State<ModelManager>,
	cookies: Cookies,
	mut req: Request<Body>,
	next: Next,
) -> Response {
	debug!("{:<12} - mw_ctx_resolve", "MIDDLEWARE");

	let ctx_ext_result = ctx_resolve(mm, &cookies).await;

	// A dead/invalid access token cookie is worthless — drop it. We keep
	// TryRefreshToken cookies intact: the client is expected to call
	// /api/refresh (using the still-valid refresh token cookie) next.
	if matches!(
		ctx_ext_result,
		Err(CtxExtError::SessionUnauthorised) | Err(CtxExtError::UserNotFound)
	) {
		clear_session_cookies(&cookies);
	}

	// Store the ctx_ext_result in the request extension
	// (for Ctx extractor).
	req.extensions_mut().insert(ctx_ext_result);

	next.run(req).await
}

async fn ctx_resolve(mm: ModelManager, cookies: &Cookies) -> CtxExtResult {
	// -- Get Access Token
	let access_token = session_cookies::access_token(cookies)
		.ok_or(CtxExtError::TokenNotInCookie)?;

	// -- Verify against SuperTokens core
	let verify_outcome = supertokens::verify_session(&access_token)
		.await
		.map_err(|ex| CtxExtError::CoreCallFailed(ex.to_string()))?;

	let (st_user_id, session_handle) = match verify_outcome {
		VerifyOutcome::Valid { user_id, session_handle } => (user_id, session_handle),
		VerifyOutcome::TryRefresh => return Err(CtxExtError::TryRefreshToken),
		VerifyOutcome::Unauthorised => return Err(CtxExtError::SessionUnauthorised),
	};

	// -- Map to our local user mirror
	let user: UserForAuth =
		UserBmc::first_by_st_user_id(&Ctx::root_ctx(), &mm, &st_user_id)
			.await
			.map_err(|ex| CtxExtError::ModelAccessError(ex.to_string()))?
			.ok_or(CtxExtError::UserNotFound)?;

	// -- Create CtxExtResult
	Ctx::new_with_session(user.id, st_user_id, session_handle)
		.map(CtxW)
		.map_err(|ex| CtxExtError::CtxCreateFail(ex.to_string()))
}

// region:    --- Ctx Extractor
#[derive(Debug, Clone)]
pub struct CtxW(pub Ctx);

impl<S: Send + Sync> FromRequestParts<S> for CtxW {
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
		debug!("{:<12} - Ctx", "EXTRACTOR");

		parts
			.extensions
			.get::<CtxExtResult>()
			.ok_or(Error::CtxExt(CtxExtError::CtxNotInRequestExt))?
			.clone()
			.map_err(Error::CtxExt)
	}
}
// endregion: --- Ctx Extractor

// region:    --- Ctx Extractor Result/Error
type CtxExtResult = core::result::Result<CtxW, CtxExtError>;

#[derive(Clone, Serialize, Debug)]
pub enum CtxExtError {
	TokenNotInCookie,

	/// Access token expired — caller should hit `/api/refresh`.
	TryRefreshToken,
	/// Session was revoked/doesn't exist in the core.
	SessionUnauthorised,

	UserNotFound,
	ModelAccessError(String),
	CoreCallFailed(String),

	CtxNotInRequestExt,
	CtxCreateFail(String),
}
// endregion: --- Ctx Extractor Result/Error
