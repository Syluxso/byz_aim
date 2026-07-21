package com.nyberg.iam.repository;

import com.nyberg.iam.domain.Device;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceRepository extends JpaRepository<Device, UUID> {

    Optional<Device> findByUserIdAndClientIdAndFingerprint(UUID userId, UUID clientId, String fingerprint);

    List<Device> findByUserIdAndRevokedFalseOrderByLastSeenAtDesc(UUID userId);

    Optional<Device> findByIdAndUserId(UUID id, UUID userId);
}
