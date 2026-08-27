use crate::middleware;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use derive_more::From;
use lib_auth::supertokens;
use lib_core::model;
use serde::Serialize;
use std::sync::Arc;
use tracing::debug;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Serialize, From, strum_macros::AsRefStr)]
#[serde(tag = "type", content = "data")]
pub enum Error {
	// -- Signup / Signin
	SignupEmailExists,
	SigninFail,
	ValidationFail(String),

	// -- Refresh
	RefreshTokenMissing,
	RefreshFail,
	SessionTokenTheftDetected,

	// -- CtxExtError
	#[from]
	CtxExt(middleware::mw_auth::CtxExtError),

	// -- Extractors
	ReqStampNotInReqExt,

	// -- Modules
	#[from]
	Model(model::Error),
	SuperTokens(#[serde(skip)] supertokens::Error),
}

impl From<supertokens::Error> for Error {
	fn from(ex: supertokens::Error) -> Self {
		match ex {
			supertokens::Error::EmailAlreadyExists => Error::SignupEmailExists,
			supertokens::Error::WrongCredentials => Error::SigninFail,
			other => Error::SuperTokens(other),
		}
	}
}

// region:    --- Error Boilerplate
impl core::fmt::Display for Error {
	fn fmt(
		&self,
		fmt: &mut core::fmt::Formatter,
	) -> core::result::Result<(), core::fmt::Error> {
		write!(fmt, "{self:?}")
	}
}

impl std::error::Error for Error {}
// endregion: --- Error Boilerplate

// region:    --- Axum IntoResponse
impl IntoResponse for Error {
	fn into_response(self) -> Response {
		debug!("{:<12} - lib_web::Error {self:?}", "INTO_RES");

		// Create a placeholder Axum reponse.
		let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();

		// Insert the Error into the reponse.
		response.extensions_mut().insert(Arc::new(self));

		response
	}
}
// endregion: --- Axum IntoResponse

// region:    --- Client Error

/// From the root error to the http status code and ClientError
impl Error {
	pub fn client_status_and_error(&self) -> (StatusCode, ClientError) {
		use Error::*; // TODO: should change to `use web::Error as E`

		match self {
			// -- Signup / Signin
			SignupEmailExists => (StatusCode::CONFLICT, ClientError::EMAIL_ALREADY_EXISTS),
			SigninFail => (StatusCode::FORBIDDEN, ClientError::LOGIN_FAIL),
			ValidationFail(msg) => (StatusCode::BAD_REQUEST, ClientError::VALIDATION_FAIL(msg.clone())),

			// -- Refresh
			RefreshTokenMissing | RefreshFail => {
				(StatusCode::UNAUTHORIZED, ClientError::NO_AUTH)
			}
			SessionTokenTheftDetected => {
				(StatusCode::UNAUTHORIZED, ClientError::SESSION_REVOKED)
			}

			// -- Auth
			CtxExt(_) => (StatusCode::UNAUTHORIZED, ClientError::NO_AUTH),

			// -- Model
			Model(model::Error::EntityNotFound { entity, id }) => (
				StatusCode::BAD_REQUEST,
				ClientError::ENTITY_NOT_FOUND { entity, id: *id },
			),

			// -- Fallback.
			_ => (
				StatusCode::INTERNAL_SERVER_ERROR,
				ClientError::SERVICE_ERROR,
			),
		}
	}
}

#[derive(Debug, Serialize, strum_macros::AsRefStr)]
#[serde(tag = "message", content = "detail")]
#[allow(non_camel_case_types)]
pub enum ClientError {
	EMAIL_ALREADY_EXISTS,
	LOGIN_FAIL,
	NO_AUTH,
	SESSION_REVOKED,
	VALIDATION_FAIL(String),
	ENTITY_NOT_FOUND { entity: &'static str, id: i64 },

	SERVICE_ERROR,
}
// endregion: --- Client Error
