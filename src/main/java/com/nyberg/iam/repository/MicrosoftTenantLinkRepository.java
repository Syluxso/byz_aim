package com.nyberg.iam.repository;

import com.nyberg.iam.domain.MicrosoftTenantLink;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface MicrosoftTenantLinkRepository extends JpaRepository<MicrosoftTenantLink, UUID> {
    Optional<MicrosoftTenantLink> findByOrganizationIdAndEntraTenantId(UUID organizationId, String entraTenantId);
}
