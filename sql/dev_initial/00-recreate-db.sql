-- DEV ONLY - Brute force reset of app schema objects (for local dev and
-- unit test). The db/role themselves are owned by docker-compose.dev.yml's
-- postgres service (POSTGRES_USER=farklin, POSTGRES_DB=farklin_auth), so
-- this only resets the objects 01-create-schema.sql recreates.
DROP TABLE IF EXISTS "user";
DROP TYPE IF EXISTS user_typ;