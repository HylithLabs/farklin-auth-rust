use derive_more::From;
use lib_core::model;
use lib_web::Error as WebError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
	#[from]
	Model(model::Error),
	#[from]
	Web(WebError),
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

impl axum::response::IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		match self {
			Error::Model(ex) => WebError::from(ex).into_response(),
			Error::Web(ex) => ex.into_response(),
		}
	}
}
