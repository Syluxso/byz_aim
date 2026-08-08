-- Snapshot of device at auth time (survives soft-delete of device rows).
ALTER TABLE iam.token_events
    ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES iam.devices(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS device_label VARCHAR(255),
    ADD COLUMN IF NOT EXISTS device_ip VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_token_events_user_created
    ON iam.token_events (user_id, created_at DESC)
    WHERE user_id IS NOT NULL;
