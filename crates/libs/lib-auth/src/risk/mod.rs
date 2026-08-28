//! Login risk check. The decision itself lives in `risk-rules/login-risk.json`
//! — a JDM decision table evaluated by `zen-engine` (gorules/zen, MIT,
//! embedded in-process — no separate service, no network call at runtime).
//! This module is just glue: build the input, run the engine, parse the
//! verdict. If the policy needs to change (e.g. what counts as risky),
//! edit the JSON — no Rust code changes, no redeploy of logic.

mod error;

pub use error::{Error, Result};

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zen_engine::loader::LoaderConfig;
use zen_engine::model::DecisionContent;
use zen_engine::DecisionEngine;

const DECISION_KEY: &str = "login-risk.json";
const DECISION_JSON: &str = include_str!("../../risk-rules/login-risk.json");

fn engine() -> &'static DecisionEngine {
	static ENGINE: OnceLock<DecisionEngine> = OnceLock::new();
	ENGINE.get_or_init(|| {
		let content: DecisionContent = serde_json::from_str(DECISION_JSON)
			.expect("login-risk.json is malformed JDM — this is a checked-in file, should never fail");

		let mut decisions = std::collections::HashMap::new();
		decisions.insert(DECISION_KEY.to_string(), content);
		let loader = LoaderConfig::Static { content: decisions }
			.into_loader()
			.expect("static loader construction cannot fail");

		DecisionEngine::default().with_loader(loader)
	})
}

#[derive(Debug, Serialize)]
struct RiskInput {
	#[serde(rename = "deviceChanged")]
	device_changed: bool,
	#[serde(rename = "ipChanged")]
	ip_changed: bool,
}

#[derive(Debug, Deserialize)]
struct RiskVerdictWire {
	outcome: String,
	reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// Nothing unusual — proceed.
	Allow,
	/// One signal changed (new IP or a new-looking device, not both).
	/// Not blocking — logged for visibility only. See login-risk.json for
	/// why: killing a session on IP-alone would log out legitimate users
	/// switching wifi/mobile constantly.
	Flag { reason: String },
	/// Both signals changed together — the "stolen session cookie replayed
	/// on a different machine" pattern. Caller should refuse the login.
	Block { reason: String },
}

/// Evaluate a login attempt against `login-risk.json`. `device_changed`
/// and `ip_changed` should already account for "first login ever" (no
/// prior fingerprint/IP to compare against) by being `false` — there's
/// nothing to flag on someone's very first signin.
///
/// `zen-engine` embeds a QuickJS runtime for its function-node feature
/// (no feature flag to turn it off — it's a hard dependency), which makes
/// its evaluation future `!Send`. That's incompatible with axum's
/// multi-threaded runtime, which requires every handler future to be
/// `Send` end to end. So this runs on its own blocking thread with a
/// throwaway single-threaded runtime — the standard way to host a `!Send`
/// future inside code that otherwise needs to stay `Send`.
pub async fn evaluate(device_changed: bool, ip_changed: bool) -> Result<Outcome> {
	tokio::task::spawn_blocking(move || {
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("failed to build a local runtime for the risk engine");
		rt.block_on(evaluate_inner(device_changed, ip_changed))
	})
	.await
	.map_err(|ex| Error::EngineFailed(format!("risk engine task panicked: {ex}")))?
}

async fn evaluate_inner(device_changed: bool, ip_changed: bool) -> Result<Outcome> {
	let input = RiskInput { device_changed, ip_changed };
	let input_value = serde_json::to_value(&input)?;

	let response = engine()
		.evaluate(DECISION_KEY, input_value.into())
		.await
		.map_err(|ex| Error::EngineFailed(ex.to_string()))?;

	let verdict: RiskVerdictWire =
		serde_json::from_value(serde_json::to_value(&response.result)?)?;

	Ok(match verdict.outcome.as_str() {
		"allow" => Outcome::Allow,
		"flag" => Outcome::Flag { reason: verdict.reason },
		"block" => Outcome::Block { reason: verdict.reason },
		other => return Err(Error::UnknownOutcome(other.to_string())),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn neither_changed_allows() {
		assert_eq!(evaluate(false, false).await.unwrap(), Outcome::Allow);
	}

	#[tokio::test]
	async fn ip_only_flags_not_blocks() {
		assert_eq!(
			evaluate(false, true).await.unwrap(),
			Outcome::Flag { reason: "ip_changed_only".into() }
		);
	}

	#[tokio::test]
	async fn device_only_flags_not_blocks() {
		assert_eq!(
			evaluate(true, false).await.unwrap(),
			Outcome::Flag { reason: "device_changed".into() }
		);
	}

	#[tokio::test]
	async fn both_changed_blocks() {
		assert_eq!(
			evaluate(true, true).await.unwrap(),
			Outcome::Block { reason: "device_and_ip_changed".into() }
		);
	}
}
