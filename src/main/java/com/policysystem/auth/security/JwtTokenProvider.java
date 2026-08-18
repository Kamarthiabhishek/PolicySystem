package com.policysystem.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * JwtTokenProvider handles JWT token generation, validation, and parsing.
 * This component is designed to be unit-testable in isolation from Spring Security.
 * 
 * Token Design:
 * - Algorithm: HS256 (symmetric secret)
 * - Access Token Claims: sub (user id), email, role, iat, exp
 * - Access Token Expiry: 15 minutes
 * - Refresh Token: opaque UUID (not a JWT), 7-day expiry, stored hashed server-side
 * - Secret: from environment variable JWT_SECRET
 */
@Slf4j
@Component
public class JwtTokenProvider {
    
    private final SecretKey secretKey;
    
    @Getter
    private final long accessTokenExpirationMs;
    
    @Getter
    private final long refreshTokenExpirationMs;
    
    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_EMAIL = "email";
    
    public JwtTokenProvider(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration.access-token:900000}") long accessTokenExpirationMs,
            @Value("${app.jwt.expiration.refresh-token:604800000}") long refreshTokenExpirationMs) {
        
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }
    
    /**
     * Generate an access token JWT with user claims.
     * 
     * @param userId the user's ID
     * @param email the user's email
     * @param role the user's role
     * @return JWT access token
     */
    public String generateAccessToken(Long userId, String email, String role) {
        Instant now = Instant.now();
        Instant expiryTime = now.plusMillis(accessTokenExpirationMs);
        
        return Jwts.builder()
                .subject(userId.toString())
                .claim(CLAIM_EMAIL, email)
                .claim(CLAIM_ROLE, role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiryTime))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
    
    /**
     * Generate a refresh token as an opaque UUID.
     * The token itself is not a JWT; it's stored hashed server-side and has a separate expiry.
     * 
     * @return opaque UUID refresh token
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Get the refresh token expiry time (for storing in database).
     * 
     * @return Instant when the refresh token expires
     */
    public Instant getRefreshTokenExpiryTime() {
        return Instant.now().plusMillis(refreshTokenExpirationMs);
    }
    
    /**
     * Validate a JWT access token and extract the user ID.
     * 
     * @param token the JWT token to validate
     * @return the user ID (subject) from the token
     * @throws JwtException if the token is invalid, expired, or signature doesn't match
     */
    public Long getUserIdFromToken(String token) {
        try {
            Claims claims = parseToken(token);
            return Long.parseLong(claims.getSubject());
        } catch (NumberFormatException e) {
            log.warn("Invalid user ID in token claim");
            throw new JwtException("Invalid token format", e);
        }
    }
    
    /**
     * Extract the email claim from a JWT token.
     * 
     * @param token the JWT token
     * @return the email claim
     * @throws JwtException if the token is invalid
     */
    public String getEmailFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.get(CLAIM_EMAIL, String.class);
    }
    
    /**
     * Extract the role claim from a JWT token.
     * 
     * @param token the JWT token
     * @return the role claim
     * @throws JwtException if the token is invalid
     */
    public String getRoleFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.get(CLAIM_ROLE, String.class);
    }
    
    /**
     * Validate a JWT token (signature, expiry).
     * This method parses the token and will throw an exception if validation fails.
     * 
     * @param token the JWT token to validate
     * @return true if token is valid
     * @throws JwtException if token is invalid or expired
     */
    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("JWT token is expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.debug("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.debug("Invalid JWT token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.debug("JWT signature validation failed: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.debug("JWT claims string is empty: {}", e.getMessage());
            throw e;
        }
    }
    
    /**
     * Parse and verify a JWT token.
     * This is a protected method used internally to extract claims.
     * 
     * @param token the JWT token to parse
     * @return the claims from the token
     * @throws JwtException if the token cannot be parsed or is invalid
     */
    protected Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
