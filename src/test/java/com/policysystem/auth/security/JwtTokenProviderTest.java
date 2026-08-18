package com.policysystem.auth.security;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JwtTokenProvider.
 * Tests token generation, validation, and parsing in isolation.
 */
@DisplayName("JwtTokenProvider Unit Tests")
class JwtTokenProviderTest {
    
    private JwtTokenProvider jwtTokenProvider;
    private static final String TEST_SECRET = "my-super-secret-key-that-is-long-enough";
    private static final long ACCESS_TOKEN_EXPIRY = 900000;  // 15 minutes
    private static final long REFRESH_TOKEN_EXPIRY = 604800000;  // 7 days
    
    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(TEST_SECRET, ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY);
    }
    
    @Test
    @DisplayName("Should generate a valid access token with correct claims")
    void testGenerateAccessToken() {
        Long userId = 1L;
        String email = "test@example.com";
        String role = "CUSTOMER";
        
        String token = jwtTokenProvider.generateAccessToken(userId, email, role);
        
        assertNotNull(token);
        assertTrue(token.contains("."));  // JWT format: header.payload.signature
        
        // Validate the token
        assertTrue(jwtTokenProvider.validateToken(token));
        
        // Extract and verify claims
        assertEquals(userId, jwtTokenProvider.getUserIdFromToken(token));
        assertEquals(email, jwtTokenProvider.getEmailFromToken(token));
        assertEquals(role, jwtTokenProvider.getRoleFromToken(token));
    }
    
    @Test
    @DisplayName("Should generate different refresh tokens each time")
    void testGenerateRefreshTokenIsUnique() {
        String token1 = jwtTokenProvider.generateRefreshToken();
        String token2 = jwtTokenProvider.generateRefreshToken();
        
        assertNotNull(token1);
        assertNotNull(token2);
        assertNotEquals(token1, token2);
    }
    
    @Test
    @DisplayName("Should extract user ID from valid token")
    void testGetUserIdFromToken() {
        Long userId = 42L;
        String token = jwtTokenProvider.generateAccessToken(userId, "test@example.com", "AGENT");
        
        Long extractedId = jwtTokenProvider.getUserIdFromToken(token);
        assertEquals(userId, extractedId);
    }
    
    @Test
    @DisplayName("Should extract email from valid token")
    void testGetEmailFromToken() {
        String email = "john@example.com";
        String token = jwtTokenProvider.generateAccessToken(1L, email, "CUSTOMER");
        
        String extractedEmail = jwtTokenProvider.getEmailFromToken(token);
        assertEquals(email, extractedEmail);
    }
    
    @Test
    @DisplayName("Should extract role from valid token")
    void testGetRoleFromToken() {
        String role = "ADMIN";
        String token = jwtTokenProvider.generateAccessToken(1L, "admin@example.com", role);
        
        String extractedRole = jwtTokenProvider.getRoleFromToken(token);
        assertEquals(role, extractedRole);
    }
    
    @Test
    @DisplayName("Should validate a valid token")
    void testValidateToken_Valid() {
        String token = jwtTokenProvider.generateAccessToken(1L, "test@example.com", "CUSTOMER");
        
        assertTrue(jwtTokenProvider.validateToken(token));
    }
    
    @Test
    @DisplayName("Should reject a malformed token")
    void testValidateToken_Malformed() {
        String malformedToken = "not.a.valid.jwt";
        
        assertThrows(JwtException.class, () -> jwtTokenProvider.validateToken(malformedToken));
    }
    
    @Test
    @DisplayName("Should reject a token with wrong signature")
    void testValidateToken_WrongSignature() {
        String token = jwtTokenProvider.generateAccessToken(1L, "test@example.com", "CUSTOMER");
        
        // Tamper with the signature
        String tamperedToken = token.substring(0, token.lastIndexOf('.')) + ".invalidsignature";
        
        assertThrows(JwtException.class, () -> jwtTokenProvider.validateToken(tamperedToken));
    }
    
    @Test
    @DisplayName("Should return correct access token expiration time")
    void testGetAccessTokenExpirationMs() {
        assertEquals(ACCESS_TOKEN_EXPIRY, jwtTokenProvider.getAccessTokenExpirationMs());
    }
    
    @Test
    @DisplayName("Should return correct refresh token expiration time")
    void testGetRefreshTokenExpirationMs() {
        assertEquals(REFRESH_TOKEN_EXPIRY, jwtTokenProvider.getRefreshTokenExpirationMs());
    }
    
    @Test
    @DisplayName("Should get refresh token expiry in the future")
    void testGetRefreshTokenExpiryTime() {
        var expiryTime = jwtTokenProvider.getRefreshTokenExpiryTime();
        var now = java.time.Instant.now();
        
        assertTrue(expiryTime.isAfter(now));
        assertTrue(expiryTime.isBefore(now.plusMillis(REFRESH_TOKEN_EXPIRY + 1000)));
    }
}
