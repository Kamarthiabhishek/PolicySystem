package com.policysystem.auth.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for updating a user's role (admin only).
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateRoleRequest {
    
    @NotNull(message = "Role is required")
    private String role;
}
