-- Device catalog: one row per user+client+fingerprint (UA/IP and optional client deviceId).
CREATE TABLE iam.devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    client_id       UUID         NOT NULL REFERENCES iam.clients(id),
    fingerprint     VARCHAR(64)  NOT NULL,
    label           VARCHAR(255) NOT NULL,
    user_agent      TEXT,
    ip_address      VARCHAR(64),
    client_device_id VARCHAR(128),
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE (user_id, client_id, fingerprint)
);

CREATE INDEX idx_devices_user ON iam.devices (user_id) WHERE revoked = FALSE;

ALTER TABLE iam.refresh_tokens
    ADD COLUMN device_id UUID REFERENCES iam.devices(id) ON DELETE SET NULL;

CREATE INDEX idx_refresh_tokens_device ON iam.refresh_tokens (device_id)
    WHERE device_id IS NOT NULL AND revoked = FALSE;
