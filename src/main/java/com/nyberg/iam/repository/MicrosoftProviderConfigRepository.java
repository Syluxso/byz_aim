package com.nyberg.iam.repository;

import com.nyberg.iam.domain.MicrosoftProviderConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MicrosoftProviderConfigRepository extends JpaRepository<MicrosoftProviderConfig, UUID> {
    Optional<MicrosoftProviderConfig> findByOrganizationId(UUID organizationId);
    List<MicrosoftProviderConfig> findAllByOrderByUpdatedAtDesc();
}
