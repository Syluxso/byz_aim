CREATE TABLE iam.password_reset_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    client_id   UUID NOT NULL REFERENCES iam.clients(id),
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_reset_tokens_user ON iam.password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_hash ON iam.password_reset_tokens(token_hash);
