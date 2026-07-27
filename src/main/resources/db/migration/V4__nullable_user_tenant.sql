-- Allow signup without an immediate workspace/tenant; apps prompt for it later.
ALTER TABLE iam.users
    ALTER COLUMN tenant_id DROP NOT NULL;
