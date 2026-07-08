package com.nyberg.iam.service;

import com.nyberg.iam.config.JwtService;
import com.nyberg.iam.domain.*;
import com.nyberg.iam.dto.*;
import com.nyberg.iam.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${iam.refresh-token-ttl-seconds}")
    private long refreshTokenTtlSeconds;

    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public TokenResponse register(RegisterRequest req) {
        Client client = resolveClient(req.clientId());
        Tenant tenant = tenantRepository.findByIdAndOrganizationIdAndActiveTrue(req.tenantId(), client.getOrganizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid tenant for organization"));

        String email = req.email().trim().toLowerCase();
        if (userRepository.existsByOrganizationIdAndEmailIgnoreCase(client.getOrganizationId(), email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered for this organization");
        }

        User user = User.builder()
                .organizationId(client.getOrganizationId())
                .tenantId(tenant.getId())
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .name(req.name().trim())
                .active(true)
                .build();
        userRepository.save(user);

        logEvent(TokenEventType.REGISTER, client.getOrganizationId(), user.getId(), client.getId());
        return issueUserTokens(user, client);
    }

    @Transactional
    public TokenResponse login(LoginRequest req) {
        Client client = resolveClient(req.clientId());
        String email = req.email().trim().toLowerCase();
        User user = userRepository.findByOrganizationIdAndEmailIgnoreCaseAndActiveTrue(client.getOrganizationId(), email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        logEvent(TokenEventType.LOGIN, client.getOrganizationId(), user.getId(), client.getId());
        return issueUserTokens(user, client);
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest req) {
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
        return issueUserTokens(user, client);
    }

    @Transactional
    public TokenResponse clientCredentials(TokenRequest req) {
        if (!"client_credentials".equals(req.grantType())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported grant_type");
        }

        Client client = resolveClient(req.clientId());
        if (client.getClientType() != ClientType.CONFIDENTIAL) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Client not allowed for client_credentials");
        }
        if (!client.supportsGrant("client_credentials")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Grant type not allowed for client");
        }
        if (client.getClientSecretHash() == null || req.clientSecret() == null
                || !passwordEncoder.matches(req.clientSecret(), client.getClientSecretHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid client credentials");
        }

        logEvent(TokenEventType.CLIENT_CREDENTIALS, client.getOrganizationId(), null, client.getId());
        String accessToken = jwtService.createServiceToken(client.getClientId(), client.getOrganizationId(), "byz-api");
        return TokenResponse.accessOnly(accessToken, jwtService.accessTokenTtlSeconds());
    }

    private TokenResponse issueUserTokens(User user, Client client) {
        String accessToken = jwtService.createUserToken(
                user.getId(), user.getOrganizationId(), user.getTenantId(), client.getClientId(), "byz-api");
        String refreshToken = createRefreshToken(user, client);
        return TokenResponse.of(accessToken, jwtService.accessTokenTtlSeconds(), refreshToken);
    }

    private String createRefreshToken(User user, Client client) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        RefreshToken token = RefreshToken.builder()
                .userId(user.getId())
                .clientId(client.getId())
                .tokenHash(hashToken(raw))
                .expiresAt(Instant.now().plusSeconds(refreshTokenTtlSeconds))
                .revoked(false)
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

    static String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}