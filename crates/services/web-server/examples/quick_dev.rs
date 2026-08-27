#![allow(unused)] // For example code.

pub type Result<T> = core::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // For examples.

use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
	let hc = httpc_test::new_client("http://localhost:8080")?;

	// -- Signup (use a fresh email each run — SuperTokens rejects a repeat)
	let email = format!("quickdev-{}@example.com", uuid_suffix());
	let req_signup = hc.do_post(
		"/api/signup",
		json!({
			"email": email,
			"password": "quick-dev-pwd-01"
		}),
	);
	req_signup.await?.print().await?;

	// -- Session check (cookies from signup carry over on this client)
	hc.do_get("/api/session").await?.print().await?;

	// -- Refresh
	hc.do_post("/api/refresh", json!({})).await?.print().await?;

	// -- Logoff
	let req_logoff = hc.do_post("/api/logoff", json!({ "logoff": true }));
	req_logoff.await?.print().await?;

	// -- Session check should now 401
	hc.do_get("/api/session").await?.print().await?;

	Ok(())
}

fn uuid_suffix() -> String {
	use std::time::{SystemTime, UNIX_EPOCH};
	let nanos = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_nanos())
		.unwrap_or_default();
	format!("{nanos:x}")
}
