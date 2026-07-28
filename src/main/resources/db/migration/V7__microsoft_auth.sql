-- Per-org Microsoft (Entra) OIDC app credentials + external identities + auth state/tickets.

CREATE TABLE iam.microsoft_provider_configs (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID         NOT NULL UNIQUE REFERENCES iam.organizations(id) ON DELETE CASCADE,
    provider              VARCHAR(50)  NOT NULL DEFAULT 'microsoft',
    credentials_encrypted TEXT         NOT NULL,
    active                BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE iam.external_identities (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        VARCHAR(50)  NOT NULL,
    subject         VARCHAR(128) NOT NULL,
    user_id         UUID         NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    organization_id UUID         NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    email           VARCHAR(320),
    entra_tenant_id VARCHAR(64),
    claims_json     TEXT,
    tokens_encrypted TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (provider, subject, organization_id)
);

CREATE INDEX idx_ext_id_user ON iam.external_identities (user_id);
CREATE INDEX idx_ext_id_entra_tid ON iam.external_identities (organization_id, entra_tenant_id);

-- Maps an Entra directory (tid) to a Byzantine tenant under a Byz org (managed-product model).
CREATE TABLE iam.microsoft_tenant_links (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID         NOT NULL REFERENCES iam.organizations(id) ON DELETE CASCADE,
    entra_tenant_id VARCHAR(64)  NOT NULL,
    tenant_id       UUID         NOT NULL REFERENCES iam.tenants(id) ON DELETE CASCADE,
    display_name    VARCHAR(255),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (organization_id, entra_tenant_id),
    UNIQUE (tenant_id)
);

CREATE TABLE iam.microsoft_auth_states (
    state           VARCHAR(128) PRIMARY KEY,
    organization_id UUID         NOT NULL,
    client_id       VARCHAR(128) NOT NULL,
    redirect_uri    TEXT         NOT NULL,
    code_verifier   VARCHAR(128) NOT NULL,
    nonce           VARCHAR(128) NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE iam.microsoft_login_tickets (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    payload_encrypted TEXT       NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_ms_auth_states_exp ON iam.microsoft_auth_states (expires_at);
CREATE INDEX idx_ms_login_tickets_exp ON iam.microsoft_login_tickets (expires_at);
