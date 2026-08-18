package com.policysystem.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for token refresh request.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshRequest {
    
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
