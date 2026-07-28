package com.nyberg.iam.service;

import com.nyberg.iam.domain.*;
import com.nyberg.iam.dto.ForgotPasswordRequest;
import com.nyberg.iam.dto.ResetPasswordRequest;
import com.nyberg.iam.events.PasswordResetRequestedApplicationEvent;
import com.nyberg.iam.events.UserLifecycleEvent;
import com.nyberg.iam.repository.PasswordResetTokenRepository;
import com.nyberg.iam.repository.RefreshTokenRepository;
import com.nyberg.iam.repository.TokenEventRepository;
import com.nyberg.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenEventRepository tokenEventRepository;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${iam.password-reset-ttl-seconds:3600}")
    private long passwordResetTtlSeconds;

    @Value("${iam.app-public-base-url:http://localhost:4200}")
    private String appPublicBaseUrl;

    /**
     * Always succeeds from the caller's perspective (no email enumeration).
     * When a matching active user exists, creates a one-time token and emits a Kafka event for email.
     */
    @Transactional
    public void forgotPassword(ForgotPasswordRequest req) {
        Client client;
        try {
            client = authService.requireActiveClient(req.clientId());
        } catch (ResponseStatusException e) {
            // Invalid client — still return quietly after validation failure would 400 from @Valid;
            // bad clientId is a client bug, rethrow so they fix it.
            throw e;
        }

        String email = req.email().trim().toLowerCase();
        userRepository.findByOrganizationIdAndEmailIgnoreCaseAndActiveTrue(client.getOrganizationId(), email)
                .ifPresent(user -> issueReset(user, client));
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest req) {
        Client client = authService.requireActiveClient(req.clientId());
        String hash = AuthService.hashToken(req.token().trim());
        PasswordResetToken stored = passwordResetTokenRepository.findByTokenHashAndUsedAtIsNull(hash)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset link"));

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset link");
        }
        if (!stored.getClientId().equals(client.getId())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset link");
        }

        User user = userRepository.findById(stored.getUserId())
                .filter(User::isActive)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset link"));

        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        userRepository.save(user);

        stored.setUsedAt(Instant.now());
        passwordResetTokenRepository.save(stored);
        passwordResetTokenRepository.invalidateUnusedForUser(user.getId(), Instant.now());
        refreshTokenRepository.revokeAllByUserId(user.getId());

        tokenEventRepository.save(TokenEvent.builder()
                .eventType(TokenEventType.PASSWORD_RESET)
                .organizationId(client.getOrganizationId())
                .userId(user.getId())
                .clientId(client.getId())
                .build());
    }

    private void issueReset(User user, Client client) {
        passwordResetTokenRepository.invalidateUnusedForUser(user.getId(), Instant.now());

        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        PasswordResetToken token = PasswordResetToken.builder()
                .userId(user.getId())
                .clientId(client.getId())
                .tokenHash(AuthService.hashToken(raw))
                .expiresAt(Instant.now().plusSeconds(passwordResetTtlSeconds))
                .build();
        passwordResetTokenRepository.save(token);

        String base = appPublicBaseUrl.endsWith("/")
                ? appPublicBaseUrl.substring(0, appPublicBaseUrl.length() - 1)
                : appPublicBaseUrl;
        String resetUrl = base + "/reset-password?token=" + raw;

        log.info("Password reset issued for userId={} orgId={} (email via Kafka; link={})",
                user.getId(), user.getOrganizationId(), resetUrl);

        applicationEventPublisher.publishEvent(new PasswordResetRequestedApplicationEvent(
                this,
                UserLifecycleEvent.passwordResetRequested(
                        user.getOrganizationId(),
                        user.getTenantId(),
                        user.getId(),
                        user.getEmail(),
                        user.getName(),
                        resetUrl
                )
        ));
    }
}
