package com.nyberg.iam.repository;

import com.nyberg.iam.domain.ExternalIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentity, UUID> {
    Optional<ExternalIdentity> findByProviderAndSubjectAndOrganizationId(
            String provider, String subject, UUID organizationId);
}
