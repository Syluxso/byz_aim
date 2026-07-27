-- On-demand API keys (appId + secret). Created explicitly; never auto-minted per user.
-- kind=user → user_id set; kind=tenant → tenant_id set. Always scoped to an organization.
CREATE TABLE iam.api_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES iam.organizations(id),
    kind             VARCHAR(20) NOT NULL,
    user_id          UUID REFERENCES iam.users(id),
    tenant_id        UUID REFERENCES iam.tenants(id),
    app_id           VARCHAR(64) NOT NULL UNIQUE,
    name             VARCHAR(255) NOT NULL,
    secret_prefix    VARCHAR(32) NOT NULL,
    secret_hash      VARCHAR(255) NOT NULL,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at       TIMESTAMPTZ,
    last_used_at     TIMESTAMPTZ,
    created_by_client_id UUID REFERENCES iam.clients(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_api_keys_kind CHECK (kind IN ('user', 'tenant')),
    CONSTRAINT chk_api_keys_subject CHECK (
        (kind = 'user' AND user_id IS NOT NULL AND tenant_id IS NULL)
        OR (kind = 'tenant' AND tenant_id IS NOT NULL AND user_id IS NULL)
    )
);

CREATE INDEX idx_api_keys_org ON iam.api_keys (organization_id);
CREATE INDEX idx_api_keys_secret_prefix ON iam.api_keys (secret_prefix) WHERE active = TRUE;
CREATE INDEX idx_api_keys_user ON iam.api_keys (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_api_keys_tenant ON iam.api_keys (tenant_id) WHERE tenant_id IS NOT NULL;
