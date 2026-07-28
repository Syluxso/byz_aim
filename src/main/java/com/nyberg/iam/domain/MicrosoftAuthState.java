package com.nyberg.iam.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "microsoft_auth_states", schema = "iam")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MicrosoftAuthState {

    @Id
    @Column(length = 128)
    private String state;

    @Column(name = "organization_id", nullable = false)
    private UUID organizationId;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "TEXT")
    private String redirectUri;

    @Column(name = "code_verifier", nullable = false, length = 128)
    private String codeVerifier;

    @Column(nullable = false, length = 128)
    private String nonce;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) createdAt = Instant.now();
    }
}
