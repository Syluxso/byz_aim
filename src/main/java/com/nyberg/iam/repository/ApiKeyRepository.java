package com.nyberg.iam.repository;

import com.nyberg.iam.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    List<ApiKey> findByOrganizationIdOrderByCreatedAtDesc(UUID organizationId);

    Optional<ApiKey> findByIdAndOrganizationId(UUID id, UUID organizationId);

    Optional<ApiKey> findByAppId(String appId);

    List<ApiKey> findBySecretPrefixAndActiveTrue(String secretPrefix);
}
