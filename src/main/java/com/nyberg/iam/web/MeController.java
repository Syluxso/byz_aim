package com.nyberg.iam.web;

import com.nyberg.iam.admin.AdminAuth;
import com.nyberg.iam.domain.User;
import com.nyberg.iam.dto.MeResponse;
import com.nyberg.iam.dto.UpdateMeRequest;
import com.nyberg.iam.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/me")
@RequiredArgsConstructor
public class MeController {

    private final UserRepository userRepository;

    @GetMapping
    public MeResponse getMe() {
        return toResponse(requireUser());
    }

    @PatchMapping
    public MeResponse updateMe(@Valid @RequestBody UpdateMeRequest req) {
        User user = requireUser();
        String email = req.email().trim().toLowerCase();

        if (!email.equalsIgnoreCase(user.getEmail())) {
            UUID orgId = user.getOrganizationId();
            userRepository.findByOrganizationIdAndEmailIgnoreCase(orgId, email)
                    .filter(other -> !other.getId().equals(user.getId()))
                    .ifPresent(other -> {
                        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
                    });
            user.setEmail(email);
        }

        if (req.name() != null && !req.name().isBlank()) {
            user.setName(req.name().trim());
        }

        return toResponse(userRepository.save(user));
    }

    private User requireUser() {
        Jwt jwt = AdminAuth.requireJwt();
        UUID userId = AdminAuth.subjectUserId(jwt);
        return userRepository.findById(userId)
                .filter(User::isActive)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
    }

    private static MeResponse toResponse(User user) {
        return new MeResponse(
                user.getId(),
                user.getOrganizationId(),
                user.getTenantId(),
                user.getEmail(),
                user.getName()
        );
    }
}
