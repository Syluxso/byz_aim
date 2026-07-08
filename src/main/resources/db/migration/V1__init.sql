CREATE TABLE iam.organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) NOT NULL UNIQUE,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam.tenants (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES iam.organizations(id),
    name             VARCHAR(255) NOT NULL,
    slug             VARCHAR(100) NOT NULL,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE iam.clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(100) NOT NULL UNIQUE,
    organization_id     UUID NOT NULL REFERENCES iam.organizations(id),
    client_secret_hash  VARCHAR(255),
    client_type         VARCHAR(20) NOT NULL,
    grant_types         VARCHAR(255) NOT NULL,
    redirect_uris       TEXT,
    name                VARCHAR(255) NOT NULL,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam.users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES iam.organizations(id),
    tenant_id        UUID NOT NULL REFERENCES iam.tenants(id),
    email            VARCHAR(320) NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, email)
);

CREATE TABLE iam.refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    client_id   UUID NOT NULL REFERENCES iam.clients(id),
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam.token_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type       VARCHAR(50) NOT NULL,
    organization_id  UUID NOT NULL REFERENCES iam.organizations(id),
    user_id          UUID REFERENCES iam.users(id),
    client_id        UUID REFERENCES iam.clients(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org_email ON iam.users(organization_id, email);
CREATE INDEX idx_token_events_org_type ON iam.token_events(organization_id, event_type, created_at);
CREATE INDEX idx_clients_org ON iam.clients(organization_id);