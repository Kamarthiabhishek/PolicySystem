package com.policysystem.auth.service;

import com.policysystem.auth.dto.AuthResponse;
import com.policysystem.auth.dto.UserResponse;
import com.policysystem.auth.entity.RefreshToken;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.exception.InvalidCredentialsException;
import com.policysystem.auth.exception.InvalidTokenException;
import com.policysystem.auth.repository.RefreshTokenRepository;
import com.policysystem.auth.repository.UserRepository;
import com.policysystem.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * AuthService handles authentication operations: login and token refresh.
 * Enforces security rules and delegates token management to JwtTokenProvider.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
    
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Authenticate a user with email and password.
     * Returns both access and refresh tokens.
     * 
     * @param email user's email
     * @param password user's password (plaintext)
     * @return AuthResponse with tokens and user info
     * @throws InvalidCredentialsException if email not found or password incorrect
     */
    public AuthResponse login(String email, String password) {
        // Never reveal which credential failed (generic 401)
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));
        
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }
        
        // Generate tokens
        String accessToken = jwtTokenProvider.generateAccessToken(
                user.getId(),
                user.getEmail(),
                user.getRole().name()
        );
        
        String refreshToken = jwtTokenProvider.generateRefreshToken();
        
        // Store refresh token (hashed) in database
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .tokenHash(com.policysystem.auth.security.TokenHasher.hash(refreshToken))
                .expiresAt(jwtTokenProvider.getRefreshTokenExpiryTime())
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
        
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtTokenProvider.getAccessTokenExpirationMs() / 1000)
                .user(UserResponse.fromUser(user))
                .build();
    }
    
    /**
     * Refresh an access token using a refresh token.
     * Implements token rotation: invalidate old refresh token, issue new one.
     * 
     * @param refreshToken the refresh token from the client
     * @return AuthResponse with new access token and optionally rotated refresh token
     * @throws InvalidTokenException if token is invalid, expired, or revoked
     */
    public AuthResponse refresh(String refreshToken) {
        // Look up the refresh token by its hash
        RefreshToken tokenEntity = refreshTokenRepository.findByTokenHash(
                com.policysystem.auth.security.TokenHasher.hash(refreshToken))
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
        
        // Check if token is still valid (not expired and not revoked)
        if (!tokenEntity.isValid()) {
            throw new InvalidTokenException("Refresh token is expired or revoked");
        }
        
        User user = tokenEntity.getUser();
        
        // Generate new access token
        String newAccessToken = jwtTokenProvider.generateAccessToken(
                user.getId(),
                user.getEmail(),
                user.getRole().name()
        );
        
        // Rotate refresh token: revoke old, issue new
        tokenEntity.setRevoked(true);
        refreshTokenRepository.save(tokenEntity);
        
        String newRefreshToken = jwtTokenProvider.generateRefreshToken();
        RefreshToken newTokenEntity = RefreshToken.builder()
                .user(user)
                .tokenHash(com.policysystem.auth.security.TokenHasher.hash(newRefreshToken))
                .expiresAt(jwtTokenProvider.getRefreshTokenExpiryTime())
                .revoked(false)
                .build();
        refreshTokenRepository.save(newTokenEntity);
        
        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(jwtTokenProvider.getAccessTokenExpirationMs() / 1000)
                .user(UserResponse.fromUser(user))
                .build();
    }
    
    /**
     * Hash a refresh token for secure storage.
     * Uses a simple hash function (in production, use bcrypt or similar).
     * 
     * @param token the plaintext token
     * @return hashed token
     */
    private String hashToken(String token) {
        return passwordEncoder.encode(token);
    }
}
