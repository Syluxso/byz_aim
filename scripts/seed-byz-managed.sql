-- Seed managed Byzantine product org + clients.
-- Run AFTER IAM Flyway has created schema.
--
--   Get-Content projects\byz-iam\scripts\seed-byz-managed.sql | docker exec -i byz-iam-db psql -U iam -d iam
--
-- Clients:
--   byz-managed-front — public SPA (password + refresh)
--   byz-managed-api   — confidential server (client_credentials + password + refresh)
--
-- Signup/login from byz-front uses byz-managed-front; omit tenantName in Phase 1.

INSERT INTO iam.organizations (id, name, slug, active)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Byz Managed', 'byz-managed', true)
ON CONFLICT (id) DO UPDATE
  SET name = EXCLUDED.name,
      slug = EXCLUDED.slug,
      active = true;

INSERT INTO iam.tenants (id, organization_id, name, slug, active)
VALUES (
  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbb0001',
  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  'Default',
  'default',
  true
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT
  'byz-managed-front',
  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  NULL,
  NULL,
  'PUBLIC',
  'password,refresh_token',
  'Byz Managed Front',
  true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'byz-managed-front');

-- Confidential API client — set a real secret via Admin rotate (placeholder hash for local only)
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT
  'byz-managed-api',
  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  NULL,
  -- bcrypt for "change-me" (local placeholder; rotate in Admin for real use)
  '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
  'CONFIDENTIAL',
  'password,refresh_token,client_credentials',
  'Byz Managed API',
  true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'byz-managed-api');
