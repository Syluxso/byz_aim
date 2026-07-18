-- Local IAM clients for Admin + events-service control plane.
-- Admin UI uses PUBLIC client byz-admin (password grant).
-- events-service confidential client is optional (client_credentials for future automation).
--
--   Get-Content projects/iam/scripts/seed-events.sql | docker exec -i byz-iam-db psql -U iam -d iam

INSERT INTO iam.organizations (id, name, slug, active)
VALUES
  ('c0000000-0000-4000-8000-000000000001', 'Byzantine', 'byzantine', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.tenants (id, organization_id, name, slug, active)
VALUES
  ('c0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000001', 'Default', 'default', true)
ON CONFLICT (id) DO NOTHING;

-- PUBLIC SPA — Byzantine Admin (local)
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'byz-admin', 'c0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000002',
       NULL, 'PUBLIC', 'password,refresh_token', 'Byzantine Admin (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'byz-admin');

-- CONFIDENTIAL — events-service automation (local secret plaintext: local-hamlet-api-secret
-- — same BCrypt as hamlet-api seed; rotate later if you want a distinct secret)
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'events-service', 'c0000000-0000-4000-8000-000000000001', NULL,
       '$2b$10$.UVNokSoDaWbWXtCy3hqrO4JRWBLCRWkLvwZY.SOyhYkywSor6BO6',
       'CONFIDENTIAL', 'client_credentials', 'Events Service (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'events-service');

UPDATE iam.clients
SET client_secret_hash = '$2b$10$.UVNokSoDaWbWXtCy3hqrO4JRWBLCRWkLvwZY.SOyhYkywSor6BO6',
    grant_types = 'client_credentials',
    client_type = 'CONFIDENTIAL',
    name = 'Events Service (local)'
WHERE client_id = 'events-service';
