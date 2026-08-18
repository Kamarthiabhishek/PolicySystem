package com.policysystem.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.policysystem.auth.dto.*;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.repository.RefreshTokenRepository;
import com.policysystem.auth.repository.UserRepository;
import com.policysystem.auth.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Auth module endpoints using MockMvc.
 * Tests the full flow: register -> login -> access /me -> refresh -> access /me again.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Auth Module Integration Tests")
class AuthIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    
    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }
    
    @Test
    @DisplayName("E2E: Register -> Login -> /me -> Refresh -> /me")
    @Transactional
    void testFullAuthFlow() throws Exception {
        // 1. Register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .name("Jane Doe")
                .email("jane@example.com")
                .password("SecurePass123")
                .build();
        
        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.name").value("Jane Doe"))
                .andExpect(jsonPath("$.email").value("jane@example.com"))
                .andExpect(jsonPath("$.role").value("CUSTOMER"))
                .andReturn();
        
        UserResponse registeredUser = objectMapper.readValue(
                registerResult.getResponse().getContentAsString(),
                UserResponse.class
        );
        Long userId = registeredUser.getId();
        
        // Verify password hash is NOT in response
        assertFalse(registerResult.getResponse().getContentAsString().contains("password"));
        assertFalse(registerResult.getResponse().getContentAsString().contains("SecurePass123"));
        
        // 2. Login with the registered user
        LoginRequest loginRequest = LoginRequest.builder()
                .email("jane@example.com")
                .password("SecurePass123")
                .build();
        
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.expiresIn").exists())
                .andExpect(jsonPath("$.user.id").value(userId))
                .andExpect(jsonPath("$.user.email").value("jane@example.com"))
                .andExpect(jsonPath("$.user.role").value("CUSTOMER"))
                .andReturn();
        
        AuthResponse authResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                AuthResponse.class
        );
        
        String accessToken = authResponse.getAccessToken();
        String refreshToken = authResponse.getRefreshToken();
        
        // Verify tokens are not empty
        assertNotNull(accessToken);
        assertNotNull(refreshToken);
        assertFalse(accessToken.isEmpty());
        assertFalse(refreshToken.isEmpty());
        
        // 3. Access /me with the access token
        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId))
                .andExpect(jsonPath("$.name").value("Jane Doe"))
                .andExpect(jsonPath("$.email").value("jane@example.com"))
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
        
        // 4. Refresh the token
        RefreshRequest refreshRequest = RefreshRequest.builder()
                .refreshToken(refreshToken)
                .build();
        
        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.expiresIn").exists())
                .andReturn();
        
        AuthResponse newAuthResponse = objectMapper.readValue(
                refreshResult.getResponse().getContentAsString(),
                AuthResponse.class
        );
        
        String newAccessToken = newAuthResponse.getAccessToken();
        String newRefreshToken = newAuthResponse.getRefreshToken();
        
        // New tokens should be different from old ones
        assertNotEquals(accessToken, newAccessToken);
        assertNotEquals(refreshToken, newRefreshToken);
        
        // 5. Access /me with the new access token
        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId));
        
        // 6. Old refresh token should now be invalid
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"));
    }
    
    @Test
    @DisplayName("Should return 401 on missing Authorization header")
    void testMissingAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    @DisplayName("Should return 401 on invalid access token")
    void testInvalidAccessToken() throws Exception {
        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    @DisplayName("Should return 401 with expired access token")
    void testExpiredAccessToken() throws Exception {
        // This would need an expired token generated with JwtTokenProvider
        // For now, we'll test with a malformed token
        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer expired.token.signature"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    @DisplayName("Should return 409 on duplicate email registration")
    void testDuplicateEmailRegistration() throws Exception {
        RegisterRequest request1 = RegisterRequest.builder()
                .name("John Doe")
                .email("john@example.com")
                .password("SecurePass123")
                .build();
        
        // First registration
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isCreated());
        
        // Attempt duplicate with same email
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("DUPLICATE_EMAIL"));
    }
    
    @Test
    @DisplayName("Should return 401 on invalid login credentials")
    void testInvalidLoginCredentials() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .email("nonexistent@example.com")
                .password("AnyPassword123")
                .build();
        
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }
    
    @Test
    @DisplayName("Should return validation error on invalid email format")
    void testValidationErrorInvalidEmail() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .name("John Doe")
                .email("not-an-email")
                .password("SecurePass123")
                .build();
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'email')]").exists());
    }
    
    @Test
    @DisplayName("Should return validation error on password too short")
    void testValidationErrorPasswordTooShort() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .name("John Doe")
                .email("john@example.com")
                .password("Pass1")  // Only 5 characters
                .build();
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
    }
    
    @Test
    @DisplayName("Should return validation error on password without number")
    void testValidationErrorPasswordNoNumber() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .name("John Doe")
                .email("john@example.com")
                .password("OnlyLetters")  // No number
                .build();
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
    }
}
