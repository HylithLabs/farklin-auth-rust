// region:    --- Modules

mod error;

pub use self::error::{Error, Result};

// endregion: --- Modules

/// Request-scoped identity. `user_id` is our local, internal id — a
/// mirror row keyed off the SuperTokens user id (see `model::user`), not
/// the SuperTokens id itself. `st_user_id`/`session_handle` are only set
/// once a real session has been resolved (never on `root_ctx`) — needed
/// by the active-devices endpoints to know "which of this user's
/// sessions is the one making this request."
#[derive(Clone, Debug)]
pub struct Ctx {
	user_id: i64,
	st_user_id: Option<String>,
	session_handle: Option<String>,
}

// Constructors.
impl Ctx {
	pub fn root_ctx() -> Self {
		Ctx { user_id: 0, st_user_id: None, session_handle: None }
	}

	pub fn new(user_id: i64) -> Result<Self> {
		if user_id == 0 {
			Err(Error::CtxCannotNewRootCtx)
		} else {
			Ok(Self { user_id, st_user_id: None, session_handle: None })
		}
	}

	/// Same as `new`, but also carries the SuperTokens identity behind
	/// this request — set by the session-verify middleware, which is the
	/// only place both are actually known.
	pub fn new_with_session(
		user_id: i64,
		st_user_id: String,
		session_handle: String,
	) -> Result<Self> {
		if user_id == 0 {
			Err(Error::CtxCannotNewRootCtx)
		} else {
			Ok(Self {
				user_id,
				st_user_id: Some(st_user_id),
				session_handle: Some(session_handle),
			})
		}
	}
}

// Property Accessors.
impl Ctx {
	pub fn user_id(&self) -> i64 {
		self.user_id
	}

	pub fn st_user_id(&self) -> Option<&str> {
		self.st_user_id.as_deref()
	}

	pub fn session_handle(&self) -> Option<&str> {
		self.session_handle.as_deref()
	}
}
