-- Per-client public base URL of the app that owns the client. Password reset
-- links use it (<base>/reset-password?token=...) so each app gets links to its
-- own site. Null keeps the platform-wide iam.app-public-base-url.
ALTER TABLE iam.clients
    ADD COLUMN IF NOT EXISTS app_base_url TEXT;
