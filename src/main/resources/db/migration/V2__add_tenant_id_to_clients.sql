ALTER TABLE iam.clients
    ADD COLUMN tenant_id UUID REFERENCES iam.tenants(id);
