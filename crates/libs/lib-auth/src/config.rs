use lib_utils::envs::get_env;
use std::env;
use std::sync::OnceLock;

pub fn auth_config() -> &'static AuthConfig {
	static INSTANCE: OnceLock<AuthConfig> = OnceLock::new();

	INSTANCE.get_or_init(|| {
		AuthConfig::load_from_env().unwrap_or_else(|ex| {
			panic!("FATAL - WHILE LOADING CONF - Cause: {ex:?}")
		})
	})
}

#[allow(non_snake_case)]
pub struct AuthConfig {
	/// Base URL of the SuperTokens core (e.g. http://localhost:3567).
	pub SUPERTOKENS_CORE_URL: String,

	/// Optional API key for the core. Only required if the core is
	/// started with `API_KEYS` set (recommended for anything beyond
	/// local dev). Sent as `Authorization: Bearer <key>`.
	pub SUPERTOKENS_API_KEY: Option<String>,
}

impl AuthConfig {
	fn load_from_env() -> lib_utils::envs::Result<AuthConfig> {
		Ok(AuthConfig {
			SUPERTOKENS_CORE_URL: get_env("SUPERTOKENS_CORE_URL")?,
			SUPERTOKENS_API_KEY: env::var("SUPERTOKENS_API_KEY").ok(),
		})
	}
}
