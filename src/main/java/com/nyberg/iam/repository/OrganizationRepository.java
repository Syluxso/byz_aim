package com.nyberg.iam.repository;

import com.nyberg.iam.domain.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface OrganizationRepository extends JpaRepository<Organization, UUID> {
    Optional<Organization> findBySlugAndActiveTrue(String slug);
}