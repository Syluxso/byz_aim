package com.nyberg.iam.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "microsoft_login_tickets", schema = "iam")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MicrosoftLoginTicket {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "payload_encrypted", nullable = false, columnDefinition = "TEXT")
    private String payloadEncrypted;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) createdAt = Instant.now();
    }
}
