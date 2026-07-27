package com.nyberg.iam.service;

import com.nyberg.iam.domain.Role;
import com.nyberg.iam.domain.User;
import com.nyberg.iam.domain.UserRole;
import com.nyberg.iam.repository.RoleRepository;
import com.nyberg.iam.repository.UserRepository;
import com.nyberg.iam.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleService {

    public static final String CLAIM_ORG_ADMIN = "org:admin";
    public static final String CLAIM_ORG_MEMBER = "org:member";
    public static final String CLAIM_TENANT_ADMIN = "tenant:admin";
    public static final String CLAIM_TENANT_USER = "tenant:user";

    private final RoleRepository roles;
    private final UserRoleRepository userRoles;
    private final UserRepository users;

    @Transactional(readOnly = true)
    public List<Role> listCatalog() {
        return roles.findAllByOrderByScopeAscNameAsc();
    }

    /**
     * Claims for JWT: all org-scoped roles for the org, plus tenant-scoped roles
     * for the token tenant (if any), plus qualified {@code tenant:role:tenantId} for every
     * tenant assignment so other tenants can authorize without Directory.
     */
    @Transactional(readOnly = true)
    public List<String> claimsForToken(UUID userId, UUID organizationId, UUID tokenTenantId) {
        List<UserRole> assigned = userRoles.findWithRoleByUserIdAndOrganizationId(userId, organizationId);
        Set<String> out = new LinkedHashSet<>();
        for (UserRole ur : assigned) {
            Role role = ur.getRole();
            if ("org".equals(role.getScope()) || "global".equals(role.getScope())) {
                out.add(role.getClaim());
            } else if ("tenant".equals(role.getScope()) && ur.getTenantId() != null) {
                out.add(role.getClaim() + ":" + ur.getTenantId());
                if (tokenTenantId != null && tokenTenantId.equals(ur.getTenantId())) {
                    out.add(role.getClaim());
                }
            }
        }
        return new ArrayList<>(out);
    }

    @Transactional(readOnly = true)
    public List<UserRole> listAssignments(UUID organizationId, UUID userId) {
        requireUserInOrg(userId, organizationId);
        return userRoles.findWithRoleByUserIdAndOrganizationId(userId, organizationId);
    }

    /** Heal legacy users: if they have no org role assignment, grant org:member. */
    @Transactional
    public void ensureOrgMemberIfMissing(User user) {
        if (!userRoles.findOrgScoped(user.getId(), user.getOrganizationId()).isEmpty()) {
            return;
        }
        replaceOrgRole(user.getId(), user.getOrganizationId(), CLAIM_ORG_MEMBER);
    }

    /** First org user becomes org:admin; otherwise org:member. Optional tenant bootstrap. */
    @Transactional
    public void assignDefaultsForNewUser(User user) {
        String orgClaim = userRoles.existsOrgClaim(user.getOrganizationId(), CLAIM_ORG_ADMIN)
                ? CLAIM_ORG_MEMBER
                : CLAIM_ORG_ADMIN;
        replaceOrgRole(user.getId(), user.getOrganizationId(), orgClaim);

        if (user.getTenantId() != null) {
            String tenantClaim = userRoles.existsTenantClaim(
                    user.getOrganizationId(), user.getTenantId(), CLAIM_TENANT_ADMIN)
                    ? CLAIM_TENANT_USER
                    : CLAIM_TENANT_ADMIN;
            replaceTenantRole(user.getId(), user.getOrganizationId(), user.getTenantId(), tenantClaim);
        }
    }

    @Transactional
    public UserRole assign(UUID organizationId, UUID userId, String claim, UUID tenantId) {
        requireUserInOrg(userId, organizationId);
        Role role = requireRoleByClaim(claim);
        UUID effectiveTenant = normalizeTenantForRole(role, tenantId);

        if ("org".equals(role.getScope())) {
            replaceOrgRole(userId, organizationId, role.getClaim());
            return userRoles.findOrgScoped(userId, organizationId).stream()
                    .filter(ur -> ur.getRole().getClaim().equals(role.getClaim()))
                    .findFirst()
                    .orElseThrow();
        }
        if ("tenant".equals(role.getScope())) {
            replaceTenantRole(userId, organizationId, effectiveTenant, role.getClaim());
            return userRoles.findTenantScoped(userId, organizationId, effectiveTenant).stream()
                    .filter(ur -> ur.getRole().getClaim().equals(role.getClaim()))
                    .findFirst()
                    .orElseThrow();
        }
        return userRoles.save(UserRole.builder()
                .userId(userId)
                .organizationId(organizationId)
                .tenantId(effectiveTenant)
                .role(role)
                .build());
    }

    /** Directory dual-write: set org role from profiles.org_role (admin|member). */
    @Transactional
    public void syncOrgRoleFromDirectory(UUID organizationId, UUID userId, String directoryOrgRole) {
        requireUserInOrg(userId, organizationId);
        String claim = "admin".equalsIgnoreCase(safe(directoryOrgRole)) ? CLAIM_ORG_ADMIN : CLAIM_ORG_MEMBER;
        replaceOrgRole(userId, organizationId, claim);
    }

    /** Directory dual-write: set tenant role from memberships.role (admin|user). */
    @Transactional
    public void syncTenantRoleFromDirectory(UUID organizationId, UUID tenantId, UUID userId, String directoryTenantRole) {
        requireUserInOrg(userId, organizationId);
        if (tenantId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenantId required");
        }
        String claim = "admin".equalsIgnoreCase(safe(directoryTenantRole)) ? CLAIM_TENANT_ADMIN : CLAIM_TENANT_USER;
        replaceTenantRole(userId, organizationId, tenantId, claim);
    }

    @Transactional
    public void revokeTenantRoles(UUID organizationId, UUID tenantId, UUID userId) {
        requireUserInOrg(userId, organizationId);
        userRoles.deleteTenantScoped(userId, organizationId, tenantId);
    }

    @Transactional
    public void revoke(UUID assignmentId) {
        UserRole ur = userRoles.findWithRoleById(assignmentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Role assignment not found"));
        userRoles.delete(ur);
    }

    @Transactional
    public List<UserRole> importAssignments(UUID organizationId, List<ImportAssignment> items) {
        List<UserRole> saved = new ArrayList<>();
        for (ImportAssignment item : items) {
            saved.add(assign(organizationId, item.userId(), item.claim(), item.tenantId()));
        }
        return saved;
    }

    private void replaceOrgRole(UUID userId, UUID organizationId, String claim) {
        Role role = requireRoleByClaim(claim);
        if (!"org".equals(role.getScope())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Not an org role: " + claim);
        }
        userRoles.deleteOrgScoped(userId, organizationId);
        userRoles.flush();
        userRoles.save(UserRole.builder()
                .userId(userId)
                .organizationId(organizationId)
                .tenantId(null)
                .role(role)
                .build());
    }

    private void replaceTenantRole(UUID userId, UUID organizationId, UUID tenantId, String claim) {
        Role role = requireRoleByClaim(claim);
        if (!"tenant".equals(role.getScope())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Not a tenant role: " + claim);
        }
        userRoles.deleteTenantScoped(userId, organizationId, tenantId);
        userRoles.flush();
        userRoles.save(UserRole.builder()
                .userId(userId)
                .organizationId(organizationId)
                .tenantId(tenantId)
                .role(role)
                .build());
    }

    private Role requireRoleByClaim(String claim) {
        String c = normalizeClaim(claim);
        return roles.findByClaim(c)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown role claim: " + c));
    }

    private void requireUserInOrg(UUID userId, UUID organizationId) {
        users.findByIdAndOrganizationId(userId, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found in organization"));
    }

    private static UUID normalizeTenantForRole(Role role, UUID tenantId) {
        if ("tenant".equals(role.getScope())) {
            if (tenantId == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenantId required for tenant roles");
            }
            return tenantId;
        }
        return null;
    }

    private static String normalizeClaim(String claim) {
        if (claim == null || claim.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "claim is required");
        }
        return claim.trim().toLowerCase(Locale.ROOT);
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    public record ImportAssignment(UUID userId, String claim, UUID tenantId) {}
}
