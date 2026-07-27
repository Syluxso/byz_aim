-- Roles catalog + per-user assignments (JWT claim source of truth).

CREATE TABLE iam.roles (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64)  NOT NULL UNIQUE,
    scope       VARCHAR(16)  NOT NULL,
    claim       VARCHAR(64)  NOT NULL UNIQUE,
    description TEXT,
    CONSTRAINT roles_scope_chk CHECK (scope IN ('org', 'tenant', 'global'))
);

CREATE TABLE iam.user_roles (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    organization_id UUID         NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    tenant_id       UUID         REFERENCES iam.tenants(id) ON DELETE CASCADE,
    role_id         UUID         NOT NULL REFERENCES iam.roles(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT user_roles_org_role_uq UNIQUE NULLS NOT DISTINCT (user_id, organization_id, tenant_id, role_id)
);

CREATE INDEX idx_user_roles_user_org ON iam.user_roles (user_id, organization_id);
CREATE INDEX idx_user_roles_org ON iam.user_roles (organization_id);
CREATE INDEX idx_user_roles_tenant ON iam.user_roles (tenant_id) WHERE tenant_id IS NOT NULL;

INSERT INTO iam.roles (id, name, scope, claim, description) VALUES
    ('a1000000-0000-4000-8000-000000000001', 'org_admin',    'org',    'org:admin',    'Organization administrator'),
    ('a1000000-0000-4000-8000-000000000002', 'org_member',   'org',    'org:member',   'Organization member'),
    ('a1000000-0000-4000-8000-000000000003', 'tenant_admin', 'tenant', 'tenant:admin', 'Tenant / workspace administrator'),
    ('a1000000-0000-4000-8000-000000000004', 'tenant_user',  'tenant', 'tenant:user',  'Tenant / workspace member');
