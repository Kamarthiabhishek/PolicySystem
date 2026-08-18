package com.policysystem.auth.controller;

import com.policysystem.auth.dto.UpdateRoleRequest;
import com.policysystem.auth.dto.UserResponse;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * UserController handles user-related endpoints: profile retrieval, listing, and role management.
 * Protected endpoints require authentication; admin endpoints require ADMIN role.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    /**
     * GET /api/v1/users/me
     * Get the current authenticated user's profile.
     * Requires authentication.
     * 
     * @return 200 OK with current user's profile
     */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getCurrentUser() {
        Long userId = getCurrentUserId();
        UserResponse userResponse = userService.getCurrentUser(userId);
        return ResponseEntity.ok(userResponse);
    }
    
    /**
     * GET /api/v1/users
     * List all users with optional role filtering.
     * Requires ADMIN role.
     * 
     * @param pageable pagination parameters (page, size, sort)
     * @param role optional role filter
     * @return 200 OK with paginated list of users
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listUsers(
            Pageable pageable,
            @RequestParam(required = false) String role) {
        
        Role roleFilter = null;
        if (role != null && !role.isEmpty()) {
            try {
                roleFilter = Role.valueOf(role.toUpperCase());
            } catch (IllegalArgumentException e) {
                // Invalid role filter, ignore
            }
        }
        
        Page<UserResponse> users = userService.listUsers(pageable, roleFilter);
        return ResponseEntity.ok(users);
    }
    
    /**
     * PATCH /api/v1/users/{id}/role
     * Change a user's role.
     * Requires ADMIN role.
     * Guards against admin self-demotion: the last remaining admin cannot demote themselves.
     * 
     * @param id the user ID to update
     * @param request the new role
     * @return 204 No Content on success
     */
    @PatchMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> updateUserRole(
            @PathVariable Long id,
            @Valid @RequestBody UpdateRoleRequest request) {
        
        Role newRole;
        try {
            newRole = Role.valueOf(request.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        
        Long adminUserId = getCurrentUserId();
        userService.changeUserRole(id, newRole, adminUserId);
        return ResponseEntity.noContent().build();
    }
    
    /**
     * Extract the current authenticated user's ID from SecurityContext.
     * 
     * @return the user ID
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof com.policysystem.auth.entity.User) {
            return ((com.policysystem.auth.entity.User) authentication.getPrincipal()).getId();
        }
        throw new IllegalStateException("Unable to determine current user");
    }
}
