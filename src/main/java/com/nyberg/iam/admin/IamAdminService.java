package com.nyberg.iam.admin;

import com.nyberg.iam.domain.*;
import com.nyberg.iam.events.UserLifecycleEvent;
import com.nyberg.iam.events.UserRegisteredApplicationEvent;
import com.nyberg.iam.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
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

    private static final String PLATFORM_CLIENT_ID = "byz-admin";

    private final OrganizationRepository orgRepo;
    private final TenantRepository tenantRepo;
    private final ClientRepository clientRepo;
    private final UserRepository userRepo;
    private final RefreshTokenRepository refreshTokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher applicationEventPublisher;

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
        String clientId = req.clientId().trim();
        if (clientId.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId is required");
        }
        if (clientRepo.existsByClientId(clientId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Client ID '" + clientId + "' already exists (must be globally unique)");
        }
        if (req.tenantId() != null) {
            tenantRepo.findByIdAndOrganizationIdAndActiveTrue(req.tenantId(), orgId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                            "tenantId does not belong to this organization (or is inactive)"));
        }

        boolean confidential = !"public".equalsIgnoreCase(req.type());
        String secret = confidential ? generateSecret() : null;

        Client client = new Client();
        client.setClientId(clientId);
        client.setOrganizationId(orgId);
        client.setTenantId(req.tenantId());
        client.setName(req.name().trim());
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

    // ── Platform operators (byz-admin org) ────────────────────────────────────

    /**
     * Users in the organization that owns the {@code byz-admin} client.
     * Any active user in that org can sign into Admin (no separate roles).
     */
    public List<OperatorUserResponse> listOperators(UUID callerOrgId) {
        UUID platformOrgId = requirePlatformOrg(callerOrgId);
        return userRepo.findByOrganizationIdOrderByCreatedAtDesc(platformOrgId).stream()
                .map(OperatorUserResponse::from)
                .toList();
    }

    @Transactional
    public OperatorUserResponse createOperator(UUID callerOrgId, CreateOperatorUserRequest req) {
        Client platform = requirePlatformClient(callerOrgId);
        UUID orgId = platform.getOrganizationId();
        UUID tenantId = platform.getTenantId();
        if (tenantId == null) {
            tenantId = tenantRepo.findAll().stream()
                    .filter(t -> orgId.equals(t.getOrganizationId()) && t.isActive())
                    .map(Tenant::getId)
                    .findFirst()
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                            "No active tenant for byz-admin organization; create one or set client tenant_id"));
        }

        String email = req.email().trim().toLowerCase();
        String name = (req.name() != null && !req.name().isBlank())
                ? req.name().trim()
                : defaultNameFromEmail(email);

        var existing = userRepo.findByOrganizationIdAndEmailIgnoreCase(orgId, email);
        if (existing.isPresent()) {
            User user = existing.get();
            if (user.isActive()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
            }
            user.setActive(true);
            user.setName(name);
            user.setPasswordHash(passwordEncoder.encode(req.password()));
            user.setTenantId(tenantId);
            User saved = userRepo.save(user);
            publishUserRegistered(saved);
            return OperatorUserResponse.from(saved);
        }

        User user = User.builder()
                .organizationId(orgId)
                .tenantId(tenantId)
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .name(name)
                .active(true)
                .build();
        User saved = userRepo.save(user);
        publishUserRegistered(saved);
        return OperatorUserResponse.from(saved);
    }

    @Transactional
    public void deactivateOperator(UUID callerOrgId, UUID userId, UUID actorUserId) {
        UUID platformOrgId = requirePlatformOrg(callerOrgId);
        if (userId.equals(actorUserId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "You cannot deactivate your own account");
        }
        User user = userRepo.findByIdAndOrganizationId(userId, platformOrgId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setActive(false);
        userRepo.save(user);
        refreshTokenRepo.revokeAllByUserId(userId);
    }

    @Transactional
    public OperatorUserResponse restoreOperator(UUID callerOrgId, UUID userId) {
        UUID platformOrgId = requirePlatformOrg(callerOrgId);
        User user = userRepo.findByIdAndOrganizationId(userId, platformOrgId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setActive(true);
        return OperatorUserResponse.from(userRepo.save(user));
    }

    @Transactional
    public void setOperatorPassword(UUID callerOrgId, UUID userId, SetOperatorPasswordRequest req) {
        UUID platformOrgId = requirePlatformOrg(callerOrgId);
        User user = userRepo.findByIdAndOrganizationId(userId, platformOrgId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setPasswordHash(passwordEncoder.encode(req.password()));
        userRepo.save(user);
        // Force re-login with the new password on other sessions.
        refreshTokenRepo.revokeAllByUserId(userId);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Client requirePlatformClient(UUID callerOrgId) {
        Client client = clientRepo.findByClientIdAndActiveTrue(PLATFORM_CLIENT_ID)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Platform client byz-admin is not configured"));
        if (!client.getOrganizationId().equals(callerOrgId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Only users in the byz-admin organization can manage operators");
        }
        return client;
    }

    private UUID requirePlatformOrg(UUID callerOrgId) {
        return requirePlatformClient(callerOrgId).getOrganizationId();
    }

    private void publishUserRegistered(User user) {
        applicationEventPublisher.publishEvent(new UserRegisteredApplicationEvent(
                this,
                UserLifecycleEvent.userRegistered(
                        user.getOrganizationId(),
                        user.getTenantId(),
                        user.getId(),
                        user.getEmail(),
                        user.getName()
                )
        ));
    }

    private static String defaultNameFromEmail(String email) {
        int at = email.indexOf('@');
        String local = at > 0 ? email.substring(0, at) : email;
        return local.isBlank() ? "Operator" : local;
    }

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
