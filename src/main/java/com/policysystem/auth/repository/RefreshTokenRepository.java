package com.policysystem.auth.repository;

import com.policysystem.auth.entity.RefreshToken;
import com.policysystem.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for RefreshToken entity operations.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    /**
     * Find a refresh token by its hash.
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    
    /**
     * Delete all refresh tokens for a specific user (logout all sessions).
     */
    void deleteAllByUser(User user);
    
    /**
     * Delete all non-revoked refresh tokens for a user.
     */
    void deleteByUserAndRevokedFalse(User user);
}
