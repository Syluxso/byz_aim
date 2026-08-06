-- Local confidential client for byz-agent → byz-fetch (client_credentials JWT).
-- Plaintext secret for local only: local-byz-agent-secret
-- BCrypt hash generated for that secret (same cost as other local seeds).
--
--   Get-Content projects\byz-iam\scripts\seed-byz-agent.sql | docker exec -i byz-iam-db psql -U iam -d iam

INSERT INTO iam.organizations (id, name, slug, active)
VALUES
  ('c0000000-0000-4000-8000-000000000001', 'Byzantine', 'byzantine', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.tenants (id, organization_id, name, slug, active)
VALUES
  ('c0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000001', 'Default', 'default', true)
ON CONFLICT (id) DO NOTHING;

-- CONFIDENTIAL — byz-agent service (local)
-- Secret plaintext: local-byz-agent-secret
-- tenant_id NULL so service JWT has no tenant claim (multi-tenant search overrides work).
INSERT INTO iam.clients (client_id, organization_id, tenant_id, client_secret_hash, client_type, grant_types, name, active)
SELECT 'byz-agent', 'c0000000-0000-4000-8000-000000000001', NULL,
       '$2b$10$G8a4rnSyRxbglw1EoGl0IeoG67eTCbGAOMJcwb4HFxGrNpTrscIw2',
       'CONFIDENTIAL', 'client_credentials', 'Byzantine Agent (local)', true
WHERE NOT EXISTS (SELECT 1 FROM iam.clients WHERE client_id = 'byz-agent');

UPDATE iam.clients
SET client_secret_hash = '$2b$10$G8a4rnSyRxbglw1EoGl0IeoG67eTCbGAOMJcwb4HFxGrNpTrscIw2',
    grant_types = 'client_credentials',
    client_type = 'CONFIDENTIAL',
    organization_id = 'c0000000-0000-4000-8000-000000000001',
    tenant_id = NULL,
    name = 'Byzantine Agent (local)',
    active = true
WHERE client_id = 'byz-agent';
