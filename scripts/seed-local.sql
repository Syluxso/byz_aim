-- Run after first app start (Flyway creates tables), or via docker exec
INSERT INTO iam.organizations (id, name, slug, active)
VALUES ('11111111-1111-1111-1111-111111111111', 'Local Test Org', 'local-test', true)
ON CONFLICT DO NOTHING;

INSERT INTO iam.tenants (id, organization_id, name, slug, active)
VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'Default', 'default', true)
ON CONFLICT DO NOTHING;

INSERT INTO iam.clients (client_id, organization_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'local-test-ios', '11111111-1111-1111-1111-111111111111', NULL, 'PUBLIC', 'password,refresh_token', 'Local Test iOS', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'local-test-ios');