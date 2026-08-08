package com.nyberg.iam.web;

import com.nyberg.iam.admin.AdminAuth;
import com.nyberg.iam.domain.TokenEvent;
import com.nyberg.iam.domain.TokenEventType;
import com.nyberg.iam.repository.TokenEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Authentication history for the signed-in user (login / register / password reset).
 */
@RestController
@RequestMapping("/api/v1/me/authentications")
@RequiredArgsConstructor
public class MeAuthEventsController {

    private static final Set<TokenEventType> AUTH_TYPES = EnumSet.of(
            TokenEventType.LOGIN,
            TokenEventType.REGISTER,
            TokenEventType.PASSWORD_RESET
    );

    private final TokenEventRepository tokenEventRepository;

    @GetMapping
    public List<AuthEventResponse> list() {
        Jwt jwt = AdminAuth.requireJwt();
        UUID userId = AdminAuth.subjectUserId(jwt);
        return tokenEventRepository
                .findByUserIdAndEventTypeInOrderByCreatedAtDesc(userId, AUTH_TYPES)
                .stream()
                .map(AuthEventResponse::from)
                .toList();
    }

    public record AuthEventResponse(
            UUID id,
            String type,
            Instant createdAt,
            UUID clientId,
            UUID deviceId,
            String deviceLabel,
            String deviceIp
    ) {
        static AuthEventResponse from(TokenEvent e) {
            return new AuthEventResponse(
                    e.getId(),
                    e.getEventType() != null ? e.getEventType().name() : "UNKNOWN",
                    e.getCreatedAt(),
                    e.getClientId(),
                    e.getDeviceId(),
                    e.getDeviceLabel(),
                    e.getDeviceIp()
            );
        }
    }
}
