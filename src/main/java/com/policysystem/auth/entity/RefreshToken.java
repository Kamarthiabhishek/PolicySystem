package com.policysystem.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * RefreshToken entity for managing server-side refresh token storage.
 * Stores hashed refresh tokens to enable logout and revocation.
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
    @Index(name = "idx_refresh_tokens_token_hash", columnList = "token_hash")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(nullable = false, unique = true, length = 255)
    private String tokenHash;
    
    @Column(nullable = false)
    private Instant expiresAt;
    
    @Column(nullable = false)
    private Boolean revoked = false;
    
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }
    
    /**
     * Check if the refresh token is still valid (not expired and not revoked).
     */
    public boolean isValid() {
        return !revoked && Instant.now().isBefore(expiresAt);
    }
}
