package com.nyberg.iam.repository;

import com.nyberg.iam.domain.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    @Query("""
            select ur from UserRole ur join fetch ur.role
            where ur.userId = :userId and ur.organizationId = :organizationId
            """)
    List<UserRole> findWithRoleByUserIdAndOrganizationId(
            @Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId);

    @Query("""
            select ur from UserRole ur join fetch ur.role
            where ur.id = :id
            """)
    Optional<UserRole> findWithRoleById(@Param("id") UUID id);

    @Query("""
            select case when count(ur) > 0 then true else false end from UserRole ur
            where ur.organizationId = :organizationId
              and ur.tenantId is null
              and ur.role.claim = :claim
            """)
    boolean existsOrgClaim(@Param("organizationId") UUID organizationId, @Param("claim") String claim);

    @Query("""
            select case when count(ur) > 0 then true else false end from UserRole ur
            where ur.organizationId = :organizationId
              and ur.tenantId = :tenantId
              and ur.role.claim = :claim
            """)
    boolean existsTenantClaim(
            @Param("organizationId") UUID organizationId,
            @Param("tenantId") UUID tenantId,
            @Param("claim") String claim);

    @Query("""
            select ur from UserRole ur join fetch ur.role
            where ur.userId = :userId
              and ur.organizationId = :organizationId
              and ur.tenantId is null
              and ur.role.scope = 'org'
            """)
    List<UserRole> findOrgScoped(
            @Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId);

    @Query("""
            select ur from UserRole ur join fetch ur.role
            where ur.userId = :userId
              and ur.organizationId = :organizationId
              and ur.tenantId = :tenantId
              and ur.role.scope = 'tenant'
            """)
    List<UserRole> findTenantScoped(
            @Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId,
            @Param("tenantId") UUID tenantId);

    @Modifying
    @Query("""
            delete from UserRole ur
            where ur.userId = :userId
              and ur.organizationId = :organizationId
              and ur.tenantId is null
              and ur.role.scope = 'org'
            """)
    void deleteOrgScoped(@Param("userId") UUID userId, @Param("organizationId") UUID organizationId);

    @Modifying
    @Query("""
            delete from UserRole ur
            where ur.userId = :userId
              and ur.organizationId = :organizationId
              and ur.tenantId = :tenantId
              and ur.role.scope = 'tenant'
            """)
    void deleteTenantScoped(
            @Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId,
            @Param("tenantId") UUID tenantId);
}
