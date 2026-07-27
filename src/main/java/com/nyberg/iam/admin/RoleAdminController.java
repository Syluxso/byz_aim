package com.nyberg.iam.admin;

import com.nyberg.iam.domain.Role;
import com.nyberg.iam.domain.UserRole;
import com.nyberg.iam.service.RoleService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/iam")
@RequiredArgsConstructor
public class RoleAdminController {

    private final RoleService roleService;

    @GetMapping("/roles")
    public List<RoleCatalogResponse> listCatalog() {
        AdminAuth.requireJwt();
        return roleService.listCatalog().stream().map(RoleCatalogResponse::from).toList();
    }

    @GetMapping("/orgs/{orgId}/users/{userId}/roles")
    public List<UserRoleResponse> listUserRoles(@PathVariable UUID orgId, @PathVariable UUID userId) {
        AdminAuth.requireJwt();
        return roleService.listAssignments(orgId, userId).stream().map(UserRoleResponse::from).toList();
    }

    @PostMapping("/orgs/{orgId}/users/{userId}/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public UserRoleResponse assign(
            @PathVariable UUID orgId,
            @PathVariable UUID userId,
            @Valid @RequestBody AssignRoleRequest req
    ) {
        AdminAuth.requireJwt();
        return UserRoleResponse.from(roleService.assign(orgId, userId, req.claim(), req.tenantId()));
    }

    /** Directory dual-write / migration helper: set org role from Directory org_role. */
    @PutMapping("/orgs/{orgId}/users/{userId}/org-role")
    public void syncOrgRole(
            @PathVariable UUID orgId,
            @PathVariable UUID userId,
            @Valid @RequestBody SyncOrgRoleRequest req
    ) {
        AdminAuth.requireJwt();
        roleService.syncOrgRoleFromDirectory(orgId, userId, req.orgRole());
    }

    /** Directory dual-write: set tenant membership role. */
    @PutMapping("/orgs/{orgId}/users/{userId}/tenant-roles/{tenantId}")
    public void syncTenantRole(
            @PathVariable UUID orgId,
            @PathVariable UUID userId,
            @PathVariable UUID tenantId,
            @Valid @RequestBody SyncTenantRoleRequest req
    ) {
        AdminAuth.requireJwt();
        roleService.syncTenantRoleFromDirectory(orgId, tenantId, userId, req.role());
    }

    @DeleteMapping("/orgs/{orgId}/users/{userId}/tenant-roles/{tenantId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revokeTenantRoles(
            @PathVariable UUID orgId,
            @PathVariable UUID userId,
            @PathVariable UUID tenantId
    ) {
        AdminAuth.requireJwt();
        roleService.revokeTenantRoles(orgId, tenantId, userId);
    }

    @DeleteMapping("/user-roles/{assignmentId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID assignmentId) {
        AdminAuth.requireJwt();
        roleService.revoke(assignmentId);
    }

    @PostMapping("/orgs/{orgId}/roles/import")
    public List<UserRoleResponse> importAssignments(
            @PathVariable UUID orgId,
            @Valid @RequestBody ImportRolesRequest req
    ) {
        AdminAuth.requireJwt();
        List<RoleService.ImportAssignment> items = req.assignments().stream()
                .map(a -> new RoleService.ImportAssignment(a.userId(), a.claim(), a.tenantId()))
                .toList();
        return roleService.importAssignments(orgId, items).stream().map(UserRoleResponse::from).toList();
    }

    public record RoleCatalogResponse(UUID id, String name, String scope, String claim, String description) {
        static RoleCatalogResponse from(Role r) {
            return new RoleCatalogResponse(r.getId(), r.getName(), r.getScope(), r.getClaim(), r.getDescription());
        }
    }

    public record UserRoleResponse(
            UUID id,
            UUID userId,
            UUID organizationId,
            UUID tenantId,
            String claim,
            String scope,
            String name,
            Instant createdAt
    ) {
        static UserRoleResponse from(UserRole ur) {
            Role r = ur.getRole();
            return new UserRoleResponse(
                    ur.getId(),
                    ur.getUserId(),
                    ur.getOrganizationId(),
                    ur.getTenantId(),
                    r.getClaim(),
                    r.getScope(),
                    r.getName(),
                    ur.getCreatedAt()
            );
        }
    }

    public record AssignRoleRequest(@NotBlank String claim, UUID tenantId) {}

    public record SyncOrgRoleRequest(@NotBlank String orgRole) {}

    public record SyncTenantRoleRequest(@NotBlank String role) {}

    public record ImportRolesRequest(@NotNull List<ImportRoleItem> assignments) {}

    public record ImportRoleItem(@NotNull UUID userId, @NotBlank String claim, UUID tenantId) {}
}
