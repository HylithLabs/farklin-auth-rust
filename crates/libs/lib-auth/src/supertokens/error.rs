pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, derive_more::From)]
pub enum Error {
	EmailAlreadyExists,
	WrongCredentials,

	/// The core returned a `status` we didn't expect for the call made.
	UnexpectedStatus(String),
	/// The core returned 200 but the body was missing a field we needed.
	UnexpectedResponse(&'static str),
	/// The core returned a non-200 status.
	CoreHttpError { status: u16, body: String },

	#[from]
	Reqwest(reqwest::Error),
}

impl core::fmt::Display for Error {
	fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
		write!(fmt, "{self:?}")
	}
}

impl std::error::Error for Error {}
