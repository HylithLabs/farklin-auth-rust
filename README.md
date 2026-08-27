# farklin-auth-rust

Identity, sessions and access control for Farklin. Authentication, sliding sessions, device fingerprinting and risk-based session security.

Part of the Farklin microservices backend. See [farklin](https://github.com/raiyanruhan/farklin) for the frontend and project context.

Status: signup/signin/refresh/logoff wired against a real SuperTokens core (Postgres-backed). Risk engine / device fingerprinting not started.

Stack: Rust (Axum), SuperTokens core (session + emailpassword engine, called directly over its REST API — no official Rust SDK exists), Postgres.

## Routes

- `POST /api/signup` `{ email, password }`
- `POST /api/signin` `{ email, password }`
- `POST /api/refresh` — rotates tokens using the `sRefreshToken` cookie
- `POST /api/logoff` `{ logoff: true }`
- `GET /api/session` — protected, returns the caller's local user id + email

All auth state lives in httpOnly cookies (`sAccessToken`, `sRefreshToken`); there is no bearer-token contract for browser clients. The gateway proxies these as-is.

## Local dev

```
docker compose -f docker-compose.dev.yml up -d
cp .env.example .env   # then fill in SERVICE_DB_URL etc.
cargo run -p web-server
```
