package com.policysystem.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for authentication response (login and refresh token responses).
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {
    
    @JsonProperty("accessToken")
    private String accessToken;
    
    @JsonProperty("refreshToken")
    private String refreshToken;
    
    @JsonProperty("expiresIn")
    private Long expiresIn;
    
    @JsonProperty("user")
    private UserResponse user;
}
