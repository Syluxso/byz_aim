package com.nyberg.iam.repository;

import com.nyberg.iam.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHashAndRevokedFalse(String tokenHash);

    @Modifying(clearAutomatically = true)
    @Query("update RefreshToken r set r.revoked = true where r.userId = :userId and r.revoked = false")
    int revokeAllByUserId(@Param("userId") UUID userId);

    @Modifying(clearAutomatically = true)
    @Query("update RefreshToken r set r.revoked = true where r.deviceId = :deviceId and r.revoked = false")
    int revokeAllByDeviceId(@Param("deviceId") UUID deviceId);
}