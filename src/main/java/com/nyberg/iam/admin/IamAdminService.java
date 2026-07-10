package com.nyberg.iam.admin;

import com.nyberg.iam.domain.*;
import com.nyberg.iam.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IamAdminService {

    private final OrganizationRepository orgRepo;
    private final TenantRepository tenantRepo;
    private final ClientRepository clientRepo;
    private final PasswordEncoder passwordEncoder;

    // ── Orgs ──────────────────────────────────────────────────────────────────

    public List<OrgResponse> listOrgs() {
        return orgRepo.findAll().stream().map(OrgResponse::from).toList();
    }

    @Transactional
    public OrgResponse createOrg(CreateOrgRequest req) {
        String slug = req.slug() != null && !req.slug().isBlank()
                ? req.slug() : slugify(req.name());
        Organization org = new Organization();
        org.setName(req.name());
        org.setSlug(slug);
        org.setActive(true);
        return OrgResponse.from(orgRepo.save(org));
    }

    @Transactional
    public void deleteOrg(UUID id) {
        Organization org = orgRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found"));
        org.setActive(false);
        orgRepo.save(org);
    }

    // ── Tenants ───────────────────────────────────────────────────────────────

    public List<TenantResponse> listTenants(UUID orgId) {
        requireOrg(orgId);
        return tenantRepo.findAll().stream()
                .filter(t -> orgId.equals(t.getOrganizationId()))
                .map(TenantResponse::from)
                .toList();
    }

    @Transactional
    public TenantResponse createTenant(UUID orgId, CreateTenantRequest req) {
        requireOrg(orgId);
        String slug = req.slug() != null && !req.slug().isBlank()
                ? req.slug() : slugify(req.name());
        Tenant tenant = new Tenant();
        tenant.setOrganizationId(orgId);
        tenant.setName(req.name());
        tenant.setSlug(slug);
        tenant.setActive(true);
        return TenantResponse.from(tenantRepo.save(tenant));
    }

    @Transactional
    public void deleteTenant(UUID orgId, UUID id) {
        Tenant t = tenantRepo.findById(id)
                .filter(ten -> orgId.equals(ten.getOrganizationId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant not found"));
        t.setActive(false);
        tenantRepo.save(t);
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    public List<ClientResponse> listClients(UUID orgId) {
        requireOrg(orgId);
        return clientRepo.findAll().stream()
                .filter(c -> orgId.equals(c.getOrganizationId()))
                .map(ClientResponse::from)
                .toList();
    }

    @Transactional
    public ClientCreatedResponse createClient(UUID orgId, CreateClientRequest req) {
        requireOrg(orgId);
        boolean confidential = !"public".equalsIgnoreCase(req.type());
        String secret = confidential ? generateSecret() : null;

        Client client = new Client();
        client.setClientId(req.clientId());
        client.setOrganizationId(orgId);
        client.setTenantId(req.tenantId());
        client.setName(req.name());
        client.setClientType(confidential ? ClientType.CONFIDENTIAL : ClientType.PUBLIC);
        client.setGrantTypes(confidential
                ? "password,refresh_token,client_credentials"
                : "password,refresh_token");
        client.setClientSecretHash(secret != null ? passwordEncoder.encode(secret) : null);
        client.setActive(true);

        return ClientCreatedResponse.from(clientRepo.save(client), secret);
    }

    @Transactional
    public ClientCreatedResponse rotateSecret(UUID orgId, UUID id) {
        Client client = clientRepo.findById(id)
                .filter(c -> orgId.equals(c.getOrganizationId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        if (client.getClientType() != ClientType.CONFIDENTIAL) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Public clients do not have secrets");
        }
        String secret = generateSecret();
        client.setClientSecretHash(passwordEncoder.encode(secret));
        return ClientCreatedResponse.from(clientRepo.save(client), secret);
    }

    @Transactional
    public void deleteClient(UUID orgId, UUID id) {
        Client client = clientRepo.findById(id)
                .filter(c -> orgId.equals(c.getOrganizationId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        client.setActive(false);
        clientRepo.save(client);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void requireOrg(UUID orgId) {
        if (!orgRepo.existsById(orgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found");
        }
    }

    private String generateSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String encoded = Base64.getEncoder().encodeToString(bytes)
                .replace("/", "").replace("+", "").replace("=", "");
        return encoded.length() >= 40 ? encoded.substring(0, 40) : encoded;
    }

    private String slugify(String name) {
        return name.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
    }
}
