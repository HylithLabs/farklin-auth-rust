//! IP → "City, Country" for the active-devices dashboard (display only,
//! same rule as `device_label`: never used for auth/risk decisions).
//!
//! Backed by the real DB-IP City Lite database (CC-BY 4.0, no account
//! needed — unlike MaxMind GeoLite2), fetched by
//! `scripts/fetch-geoip-db.sh` into `data/dbip-city-lite.mmdb`. Not
//! embedded in the binary (130MB, republished monthly) — loaded once at
//! first use from `GEOIP_DB_PATH`, or that default path relative to this
//! crate.
//!
//! Private/loopback IPs (`::1`, `127.0.0.1`, `10.x`, ...) simply aren't in
//! a public geo database, so they naturally resolve to `None` — no
//! special-casing needed.

use maxminddb::geoip2;
use std::env;
use std::sync::OnceLock;

fn default_db_path() -> String {
	concat!(env!("CARGO_MANIFEST_DIR"), "/data/dbip-city-lite.mmdb").to_string()
}

fn reader() -> &'static Option<maxminddb::Reader<Vec<u8>>> {
	static READER: OnceLock<Option<maxminddb::Reader<Vec<u8>>>> = OnceLock::new();
	READER.get_or_init(|| {
		let path = env::var("GEOIP_DB_PATH").unwrap_or_else(|_| default_db_path());
		match maxminddb::Reader::open_readfile(&path) {
			Ok(r) => Some(r),
			Err(e) => {
				// Missing db shouldn't take the dashboard down — just show
				// no location, same as an unresolvable/private IP would.
				tracing::warn!("geoip db not loaded from {path}: {e} (run scripts/fetch-geoip-db.sh)");
				None
			}
		}
	})
}

/// `"Dhaka, Bangladesh"`, `"Bangladesh"` (city unknown), or `None` (IP
/// unparsable, private/loopback, or db unavailable).
pub fn locate(ip: &str) -> Option<String> {
	let reader = reader().as_ref()?;
	let addr: std::net::IpAddr = ip.parse().ok()?;
	let city: geoip2::City = reader.lookup(addr).ok()?;

	let city_name = city.city.as_ref().and_then(|c| c.names.as_ref()).and_then(|n| n.get("en")).map(|s| s.to_string());
	let country_name =
		city.country.as_ref().and_then(|c| c.names.as_ref()).and_then(|n| n.get("en")).map(|s| s.to_string());

	match (city_name, country_name) {
		(Some(c), Some(co)) => Some(format!("{c}, {co}")),
		(Some(c), None) => Some(c),
		(None, Some(co)) => Some(co),
		(None, None) => None,
	}
}
