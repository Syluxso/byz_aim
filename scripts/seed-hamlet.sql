-- Hamlet platform org + clients (IAM).
-- Run AFTER IAM Flyway migrations.
--
--   Get-Content projects/iam/scripts/seed-hamlet.sql | docker exec -i byz-iam-db psql -U iam -d iam

INSERT INTO iam.organizations (id, name, slug, active)
VALUES
  ('b0000000-0000-4000-8000-000000000001', 'Hamlet', 'hamlet', true)
ON CONFLICT (id) DO NOTHING;

-- Keep slug/name correct if an earlier seed used hamlet-app
UPDATE iam.organizations
SET name = 'Hamlet', slug = 'hamlet'
WHERE id = 'b0000000-0000-4000-8000-000000000001';

-- PUBLIC SPA client (no secret)
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'hamlet-frontend', 'b0000000-0000-4000-8000-000000000001', NULL,
       NULL, 'PUBLIC', 'password,refresh_token', 'Hamlet Frontend (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'hamlet-frontend');

-- CONFIDENTIAL service client — secret plaintext for local only: local-hamlet-api-secret
-- BCrypt hash below is for "local-hamlet-api-secret" (strength 10).
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'hamlet-api', 'b0000000-0000-4000-8000-000000000001', NULL,
       '$2b$10$.UVNokSoDaWbWXtCy3hqrO4JRWBLCRWkLvwZY.SOyhYkywSor6BO6',
       'CONFIDENTIAL', 'client_credentials', 'Hamlet API (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'hamlet-api');

-- Ensure existing local hamlet-api row has the real hash (re-seed safe)
UPDATE iam.clients
SET client_secret_hash = '$2b$10$.UVNokSoDaWbWXtCy3hqrO4JRWBLCRWkLvwZY.SOyhYkywSor6BO6'
WHERE client_id = 'hamlet-api';
