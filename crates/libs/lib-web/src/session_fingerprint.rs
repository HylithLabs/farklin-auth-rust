//! What gets stored in a session's `userDataInDatabase` (SuperTokens
//! core's own Postgres, not ours — see `lib_auth::supertokens::create_session`).
//! Captured once at signin/signup, read back by the active-devices
//! dashboard. Separate from `lib_auth::risk`'s baseline (`user.last_ip`/
//! `last_visitor_id`) — that one baseline is compared against on *every*
//! signin for the risk check; this is a per-session snapshot for display.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFingerprint {
	pub ip: Option<String>,
	pub visitor_id: Option<String>,
	pub user_agent: Option<String>,
}
