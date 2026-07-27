package com.nyberg.iam.repository;

import com.nyberg.iam.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByClaim(String claim);
    Optional<Role> findByName(String name);
    List<Role> findAllByOrderByScopeAscNameAsc();
}
