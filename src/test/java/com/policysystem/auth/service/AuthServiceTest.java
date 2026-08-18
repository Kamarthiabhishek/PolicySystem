package com.policysystem.auth.service;

import com.policysystem.auth.dto.AuthResponse;
import com.policysystem.auth.entity.RefreshToken;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.exception.InvalidCredentialsException;
import com.policysystem.auth.exception.InvalidTokenException;
import com.policysystem.auth.repository.RefreshTokenRepository;
import com.policysystem.auth.repository.UserRepository;
import com.policysystem.auth.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Unit Tests")
class AuthServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    
    @Mock
    private JwtTokenProvider jwtTokenProvider;
    
    private PasswordEncoder passwordEncoder;
    private AuthService authService;
    
    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(10);
        authService = new AuthService(userRepository, refreshTokenRepository, jwtTokenProvider, passwordEncoder);
    }
    
    @Test
    @DisplayName("Should login successfully with correct credentials")
    void testLogin_Success() {
        String email = "john@example.com";
        String password = "SecurePass123";
        String hashedPassword = passwordEncoder.encode(password);
        
        User mockUser = User.builder()
                .id(1L)
                .name("John Doe")
                .email(email)
                .passwordHash(hashedPassword)
                .role(Role.CUSTOMER)
                .build();
        
        String accessToken = "access-token-jwt";
        String refreshToken = "refresh-token-uuid";
        Instant expiryTime = Instant.now().plusSeconds(604800);
        
        when(userRepository.findByEmailIgnoreCase(email)).thenReturn(Optional.of(mockUser));
        when(jwtTokenProvider.generateAccessToken(1L, email, "CUSTOMER")).thenReturn(accessToken);
        when(jwtTokenProvider.generateRefreshToken()).thenReturn(refreshToken);
        when(jwtTokenProvider.getRefreshTokenExpiryTime()).thenReturn(expiryTime);
        when(jwtTokenProvider.getAccessTokenExpirationMs()).thenReturn(900000L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        
        AuthResponse response = authService.login(email, password);
        
        assertNotNull(response);
        assertEquals(accessToken, response.getAccessToken());
        assertEquals(refreshToken, response.getRefreshToken());
        assertEquals(900L, response.getExpiresIn());
        assertNotNull(response.getUser());
        assertEquals(1L, response.getUser().getId());
        assertEquals("John Doe", response.getUser().getName());
        assertEquals("CUSTOMER", response.getUser().getRole());
        
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }
    
    @Test
    @DisplayName("Should reject login with wrong password")
    void testLogin_WrongPassword() {
        String email = "john@example.com";
        String correctPassword = "SecurePass123";
        String wrongPassword = "WrongPass456";
        
        User mockUser = User.builder()
                .id(1L)
                .name("John Doe")
                .email(email)
                .passwordHash(passwordEncoder.encode(correctPassword))
                .role(Role.CUSTOMER)
                .build();
        
        when(userRepository.findByEmailIgnoreCase(email)).thenReturn(Optional.of(mockUser));
        
        assertThrows(InvalidCredentialsException.class, () ->
                authService.login(email, wrongPassword)
        );
        
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }
    
    @Test
    @DisplayName("Should reject login with non-existent email")
    void testLogin_UserNotFound() {
        String email = "nonexistent@example.com";
        String password = "AnyPass123";
        
        when(userRepository.findByEmailIgnoreCase(email)).thenReturn(Optional.empty());
        
        assertThrows(InvalidCredentialsException.class, () ->
                authService.login(email, password)
        );
        
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }
    
    @Test
    @DisplayName("Should reject generic 401 for both user-not-found and wrong-password")
    void testLogin_GenericUnauthorized() {
        String wrongEmailMessage = null;
        String wrongPasswordMessage = null;
        
        // Test non-existent user
        when(userRepository.findByEmailIgnoreCase("nonexistent@example.com"))
                .thenReturn(Optional.empty());
        
        try {
            authService.login("nonexistent@example.com", "password");
        } catch (InvalidCredentialsException e) {
            wrongEmailMessage = e.getMessage();
        }
        
        // Test wrong password
        User mockUser = User.builder()
                .id(1L)
                .email("exists@example.com")
                .passwordHash(passwordEncoder.encode("CorrectPass123"))
                .role(Role.CUSTOMER)
                .build();
        
        when(userRepository.findByEmailIgnoreCase("exists@example.com"))
                .thenReturn(Optional.of(mockUser));
        
        try {
            authService.login("exists@example.com", "WrongPass456");
        } catch (InvalidCredentialsException e) {
            wrongPasswordMessage = e.getMessage();
        }
        
        // Both should have the same generic message
        assertEquals(wrongEmailMessage, wrongPasswordMessage);
        assertEquals("Invalid credentials", wrongEmailMessage);
    }
    
    @Test
    @DisplayName("Should refresh token successfully with token rotation")
    void testRefresh_Success() {
        String oldRefreshToken = "old-refresh-token";
        String newRefreshToken = "new-refresh-token";
        String newAccessToken = "new-access-token";
        Instant expiryTime = Instant.now().plusSeconds(604800);
        
        User mockUser = User.builder()
                .id(1L)
                .name("John Doe")
                .email("john@example.com")
                .role(Role.CUSTOMER)
                .build();
        
        RefreshToken oldTokenEntity = RefreshToken.builder()
                .id(1L)
                .user(mockUser)
                .tokenHash(com.policysystem.auth.security.TokenHasher.hash(oldRefreshToken))
                .expiresAt(expiryTime)
                .revoked(false)
                .build();
        
        when(refreshTokenRepository.findByTokenHash(
                com.policysystem.auth.security.TokenHasher.hash(oldRefreshToken)))
                .thenReturn(Optional.of(oldTokenEntity));
        when(jwtTokenProvider.generateAccessToken(1L, "john@example.com", "CUSTOMER"))
                .thenReturn(newAccessToken);
        when(jwtTokenProvider.generateRefreshToken()).thenReturn(newRefreshToken);
        when(jwtTokenProvider.getRefreshTokenExpiryTime()).thenReturn(expiryTime);
        when(jwtTokenProvider.getAccessTokenExpirationMs()).thenReturn(900000L);
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        
        AuthResponse response = authService.refresh(oldRefreshToken);
        
        assertNotNull(response);
        assertEquals(newAccessToken, response.getAccessToken());
        assertEquals(newRefreshToken, response.getRefreshToken());
        assertEquals(900L, response.getExpiresIn());
        
        // Verify old token was revoked
        assertTrue(oldTokenEntity.getRevoked());
        
        // Verify new token was saved
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }
    
    @Test
    @DisplayName("Should reject refresh with expired token")
    void testRefresh_ExpiredToken() {
        String expiredRefreshToken = "expired-token";
        
        RefreshToken expiredTokenEntity = RefreshToken.builder()
                .id(1L)
                .tokenHash("hashed-token")
                .expiresAt(Instant.now().minusSeconds(1000))  // Expired
                .revoked(false)
                .build();
        
        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(expiredTokenEntity));
        
        assertThrows(InvalidTokenException.class, () ->
                authService.refresh(expiredRefreshToken)
        );
        
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }
    
    @Test
    @DisplayName("Should reject refresh with revoked token")
    void testRefresh_RevokedToken() {
        String revokedRefreshToken = "revoked-token";
        
        RefreshToken revokedTokenEntity = RefreshToken.builder()
                .id(1L)
                .tokenHash("hashed-token")
                .expiresAt(Instant.now().plusSeconds(1000))
                .revoked(true)  // Revoked
                .build();
        
        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(revokedTokenEntity));
        
        assertThrows(InvalidTokenException.class, () ->
                authService.refresh(revokedRefreshToken)
        );
    }
    
    @Test
    @DisplayName("Should reject refresh with non-existent token")
    void testRefresh_TokenNotFound() {
        String unknownToken = "unknown-token";
        
        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.empty());
        
        assertThrows(InvalidTokenException.class, () ->
                authService.refresh(unknownToken)
        );
    }
}
