//! Human-readable device labels for the active-devices dashboard
//! ("Chrome on Windows"). Pure display — never used for any risk/auth
//! decision (see `lib_auth::risk` for why: UA strings are unreliable
//! enough that we deliberately don't trust them for security there).
//! Uses the real ua-parser project's own regex database
//! (`data/ua-regexes.yaml`, from <https://github.com/ua-parser/uap-core>)
//! via the `ua-parser` crate — cloned data and a cloned parser, not
//! hand-written parsing logic.

use std::sync::OnceLock;
use ua_parser::{Extractor, Regexes};

const REGEXES_YAML: &str = include_str!("../data/ua-regexes.yaml");

fn extractor() -> &'static Extractor<'static> {
	static EXTRACTOR: OnceLock<Extractor<'static>> = OnceLock::new();
	EXTRACTOR.get_or_init(|| {
		let regexes: Regexes<'static> = serde_yaml::from_str(REGEXES_YAML).expect(
			"data/ua-regexes.yaml is malformed — this is a checked-in file, should never fail",
		);
		Extractor::try_from(regexes)
			.expect("data/ua-regexes.yaml produced an invalid extractor — should never fail")
	})
}

/// `None` if there's no user agent to parse, or nothing matched it —
/// display "Unknown device" or similar, this isn't an error condition.
pub fn device_label(user_agent: Option<&str>) -> Option<String> {
	let ua = user_agent?;
	let (browser, os, _device) = extractor().extract(ua);

	let browser_name = browser.map(|b| b.family.into_owned());
	let os_name = os.map(|o| o.os.into_owned());

	match (browser_name, os_name) {
		(Some(b), Some(o)) => Some(format!("{b} on {o}")),
		(Some(b), None) => Some(b),
		(None, Some(o)) => Some(o),
		(None, None) => None,
	}
}
