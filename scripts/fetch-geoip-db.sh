#!/usr/bin/env bash
# Downloads the DB-IP City Lite database used for the active-devices
# dashboard's location display (see lib_web::geo_ip). Free, CC-BY 4.0,
# no account/license key needed — unlike MaxMind GeoLite2. Republished
# monthly by DB-IP; this always grabs the current month's file.
#
# Not committed to git (130MB uncompressed) — run this once per checkout,
# or on container build. See crates/libs/lib-web/data/.gitignore rule.
set -euo pipefail

DATA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/libs/lib-web/data"
MONTH="$(date +%Y-%m)"
URL="https://download.db-ip.com/free/dbip-city-lite-${MONTH}.mmdb.gz"
OUT="${DATA_DIR}/dbip-city-lite.mmdb"

mkdir -p "$DATA_DIR"
echo "Fetching ${URL}"
curl -sL "$URL" -o "${OUT}.gz"
gunzip -f "${OUT}.gz"
echo "GeoIP db ready at ${OUT}"
