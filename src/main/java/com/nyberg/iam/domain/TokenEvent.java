package com.nyberg.iam.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "token_events", schema = "iam")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    private TokenEventType eventType;

    @Column(name = "organization_id", nullable = false)
    private UUID organizationId;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "client_id")
    private UUID clientId;

    /** Optional link to device catalog; may be null for non-session events. */
    @Column(name = "device_id")
    private UUID deviceId;

    /** Snapshot at event time (device may later be soft-deleted). */
    @Column(name = "device_label")
    private String deviceLabel;

    @Column(name = "device_ip", length = 64)
    private String deviceIp;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) createdAt = Instant.now();
    }
}