package com.nyberg.iam.repository;

import com.nyberg.iam.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByOrganizationIdAndEmailIgnoreCaseAndActiveTrue(UUID organizationId, String email);
    Optional<User> findByOrganizationIdAndEmailIgnoreCase(UUID organizationId, String email);
    Optional<User> findByIdAndOrganizationId(UUID id, UUID organizationId);
    List<User> findByOrganizationIdOrderByCreatedAtDesc(UUID organizationId);
    boolean existsByOrganizationIdAndEmailIgnoreCase(UUID organizationId, String email);
}