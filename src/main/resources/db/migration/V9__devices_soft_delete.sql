-- Soft-delete: allow a new active row with the same fingerprint after revoke.
-- Previously UNIQUE (user_id, client_id, fingerprint) forced re-using (resurrecting) revoked rows.

ALTER TABLE iam.devices
    DROP CONSTRAINT IF EXISTS devices_user_id_client_id_fingerprint_key;

-- Postgres auto-name for UNIQUE (user_id, client_id, fingerprint) can vary; drop any unique on those cols.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        JOIN pg_namespace n ON t.relnamespace = n.oid
        WHERE n.nspname = 'iam'
          AND t.relname = 'devices'
          AND c.contype = 'u'
    LOOP
        EXECUTE format('ALTER TABLE iam.devices DROP CONSTRAINT IF EXISTS %I', r.conname);
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_active_fingerprint
    ON iam.devices (user_id, client_id, fingerprint)
    WHERE revoked = FALSE;
