-- Local seed for NyTech PM + a generic test client.
-- Run AFTER IAM has started once (Flyway creates schema).
--
--   docker exec -i byz-iam-db psql -U iam -d iam < projects/iam/scripts/seed-local.sql

INSERT INTO iam.organizations (id, name, slug, active)
VALUES
  ('11111111-1111-1111-1111-111111111111', 'Local Test Org', 'local-test', true),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Nytech PM Local', 'nytech-pm', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.tenants (id, organization_id, name, slug, active)
VALUES
  ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'Default', 'default', true),
  ('10723404-1607-4ba2-8bc5-fd076f0b831e', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Nytech PM', 'nytech-pm', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'local-test-ios', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222',
       NULL, 'PUBLIC', 'password,refresh_token', 'Local Test iOS', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'local-test-ios');

INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'nytech-pm-frontend', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '10723404-1607-4ba2-8bc5-fd076f0b831e',
       NULL, 'PUBLIC', 'password,refresh_token', 'Nytech PM Frontend (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'nytech-pm-frontend');
