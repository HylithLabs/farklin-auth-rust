pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, derive_more::From)]
pub enum Error {
	EngineFailed(String),
	/// login-risk.json produced an `outcome` value this code doesn't
	/// recognize — meant to fail loudly (a JSON edit typo) rather than
	/// silently fall through to some default behavior.
	UnknownOutcome(String),

	#[from]
	SerdeJson(serde_json::Error),
}

impl core::fmt::Display for Error {
	fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
		write!(fmt, "{self:?}")
	}
}

impl std::error::Error for Error {}
