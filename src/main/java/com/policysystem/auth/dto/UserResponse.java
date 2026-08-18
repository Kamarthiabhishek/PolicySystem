package com.policysystem.auth.dto;

import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for user profile response (does NOT include password hash).
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    
    private Long id;
    private String name;
    private String email;
    private String role;
    
    /**
     * Factory method to create UserResponse from a User entity.
     */
    public static UserResponse fromUser(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
}
