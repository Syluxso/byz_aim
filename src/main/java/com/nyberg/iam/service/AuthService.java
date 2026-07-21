package com.nyberg.iam.service;

import com.nyberg.iam.config.JwtService;
import com.nyberg.iam.device.DeviceHints;
import com.nyberg.iam.device.DeviceService;
import com.nyberg.iam.domain.*;
import com.nyberg.iam.dto.*;
import com.nyberg.iam.events.UserLifecycleEvent;
import com.nyberg.iam.events.UserRegisteredApplicationEvent;
import com.nyberg.iam.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final ClientRepository clientRepository;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenEventRepository tokenEventRepository;
    private final DeviceService deviceService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final ApplicationEventPublisher applicationEventPublisher;

    @Value("${iam.refresh-token-ttl-seconds}")
    private long refreshTokenTtlSeconds;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public TokenResponse register(RegisterRequest req, DeviceHints hints) {
        Client client = resolveClient(req.clientId());
        Tenant tenant = tenantRepository.findByIdAndOrganizationIdAndActiveTrue(req.tenantId(), client.getOrganizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid tenant for organization"));

        String email = req.email().trim().toLowerCase();
        if (userRepository.existsByOrganizationIdAndEmailIgnoreCase(client.getOrganizationId(), email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered for this organization");
        }

        String name = (req.name() != null && !req.name().isBlank())
                ? req.name().trim()
                : defaultNameFromEmail(email);

        User user = User.builder()
                .organizationId(client.getOrganizationId())
                .tenantId(tenant.getId())
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .name(name)
                .active(true)
                .build();
        userRepository.save(user);

        logEvent(TokenEventType.REGISTER, client.getOrganizationId(), user.getId(), client.getId());
        publishUserRegistered(user);
        return issueUserTokens(user, client, hints);
    }

    /**
     * Platform signup: create a new tenant under the client's organization, then register the user.
     * Directory profile / membership is bootstrapped by the client after tokens are issued.
     */
    @Transactional
    public TokenResponse signup(SignupRequest req, DeviceHints hints) {
        Client client = resolveClient(req.clientId());
        UUID orgId = client.getOrganizationId();

        String email = req.email().trim().toLowerCase();
        if (userRepository.existsByOrganizationIdAndEmailIgnoreCase(orgId, email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered for this organization");
        }

        String tenantName = req.tenantName().trim();
        if (tenantName.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenantName is required");
        }

        String baseSlug = slugify(tenantName);
        if (baseSlug.isBlank()) {
            baseSlug = "tenant";
        }
        String slug = uniqueTenantSlug(orgId, baseSlug);

        Tenant tenant = Tenant.builder()
                .organizationId(orgId)
                .name(tenantName)
                .slug(slug)
                .active(true)
                .build();
        tenantRepository.save(tenant);

        String name = displayName(req.firstName(), req.lastName(), email);

        User user = User.builder()
                .organizationId(orgId)
                .tenantId(tenant.getId())
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .name(name)
                .active(true)
                .build();
        userRepository.save(user);

        logEvent(TokenEventType.REGISTER, orgId, user.getId(), client.getId());
        publishUserRegistered(user);
        return issueUserTokens(user, client, hints);
    }

    @Transactional
    public TokenResponse login(LoginRequest req, DeviceHints hints) {
        Client client = resolveClient(req.clientId());
        String email = req.email().trim().toLowerCase();
        User user = userRepository.findByOrganizationIdAndEmailIgnoreCaseAndActiveTrue(client.getOrganizationId(), email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        logEvent(TokenEventType.LOGIN, client.getOrganizationId(), user.getId(), client.getId());
        return issueUserTokens(user, client, hints);
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest req, DeviceHints hints) {
        Client client = resolveClient(req.clientId());
        String hash = hashToken(req.refreshToken());
        RefreshToken stored = refreshTokenRepository.findByTokenHashAndRevokedFalse(hash)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        if (stored.getExpiresAt().isBefore(Instant.now()) || !stored.getClientId().equals(client.getId())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        User user = userRepository.findById(stored.getUserId())
                .filter(User::isActive)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        logEvent(TokenEventType.REFRESH, client.getOrganizationId(), user.getId(), client.getId());
        return issueUserTokens(user, client, hints);
    }

    @Transactional
    public TokenResponse token(TokenRequest req) {
        String grant = req.grantType().trim();
        if ("client_credentials".equals(grant)) {
            return clientCredentials(req);
        }
        if ("subject".equals(grant) || "urn:byz:params:oauth:grant-type:subject".equals(grant)) {
            return subjectToken(req);
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported grant_type");
    }

    @Transactional
    public TokenResponse clientCredentials(TokenRequest req) {
        Client client = authenticateConfidentialClient(req);
        if (!client.supportsGrant("client_credentials")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Grant type not allowed for client");
        }

        logEvent(TokenEventType.CLIENT_CREDENTIALS, client.getOrganizationId(), null, client.getId());
        String accessToken = jwtService.createServiceToken(
                client.getClientId(), client.getOrganizationId(), client.getTenantId(), "byz-api");
        return TokenResponse.accessOnly(accessToken, jwtService.accessTokenTtlSeconds());
    }

    /**
     * Mint a short-lived JWT whose {@code sub} is an external recipient UUID.
     * No IAM user row is created or required. Confidential client only.
     */
    @Transactional
    public TokenResponse subjectToken(TokenRequest req) {
        if (req.subject() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "subject (UUID) is required for subject grant");
        }
        Client client = authenticateConfidentialClient(req);

        logEvent(TokenEventType.SUBJECT, client.getOrganizationId(), null, client.getId());
        String accessToken = jwtService.createSubjectToken(
                req.subject(),
                client.getOrganizationId(),
                client.getTenantId(),
                client.getClientId(),
                "byz-api");
        return TokenResponse.accessOnly(accessToken, jwtService.subjectTokenTtlSeconds());
    }

    private Client authenticateConfidentialClient(TokenRequest req) {
        Client client = resolveClient(req.clientId());
        if (client.getClientType() != ClientType.CONFIDENTIAL) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Client not allowed for this grant");
        }
        if (client.getClientSecretHash() == null || req.clientSecret() == null
                || !passwordEncoder.matches(req.clientSecret(), client.getClientSecretHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid client credentials");
        }
        return client;
    }

    private static String defaultNameFromEmail(String email) {
        int at = email.indexOf('@');
        String local = at > 0 ? email.substring(0, at) : email;
        return local.isBlank() ? "User" : local;
    }

    private static String displayName(String firstName, String lastName, String email) {
        String combined = ((firstName == null ? "" : firstName.trim()) + " "
                + (lastName == null ? "" : lastName.trim())).trim();
        return combined.isBlank() ? defaultNameFromEmail(email) : combined;
    }

    private static String slugify(String input) {
        return input.trim().toLowerCase()
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
    }

    private String uniqueTenantSlug(UUID organizationId, String baseSlug) {
        String candidate = baseSlug;
        int i = 2;
        while (tenantRepository.findByOrganizationIdAndSlugIgnoreCase(organizationId, candidate).isPresent()) {
            candidate = baseSlug + "-" + i;
            i++;
            if (i > 1000) {
                candidate = baseSlug + "-" + UUID.randomUUID().toString().substring(0, 8);
                break;
            }
        }
        return candidate;
    }

    private TokenResponse issueUserTokens(User user, Client client, DeviceHints hints) {
        var device = deviceService.touch(user, client, hints != null ? hints : DeviceHints.empty());
        String accessToken = jwtService.createUserToken(
                user.getId(), user.getOrganizationId(), user.getTenantId(), client.getClientId(), "byz-api");
        String refreshToken = createRefreshToken(user, client, device.getId());
        return TokenResponse.of(accessToken, jwtService.accessTokenTtlSeconds(), refreshToken);
    }

    private String createRefreshToken(User user, Client client, UUID deviceId) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        RefreshToken token = RefreshToken.builder()
                .userId(user.getId())
                .clientId(client.getId())
                .tokenHash(hashToken(raw))
                .expiresAt(Instant.now().plusSeconds(refreshTokenTtlSeconds))
                .revoked(false)
                .deviceId(deviceId)
                .build();
        refreshTokenRepository.save(token);
        return raw;
    }

    private Client resolveClient(String clientId) {
        return clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client_id"));
    }

    private void logEvent(TokenEventType type, UUID organizationId, UUID userId, UUID clientId) {
        tokenEventRepository.save(TokenEvent.builder()
                .eventType(type)
                .organizationId(organizationId)
                .userId(userId)
                .clientId(clientId)
                .build());
    }

    /** Published as Spring event; Kafka send runs AFTER_COMMIT so rollbacks do not emit. */
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

    static String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}