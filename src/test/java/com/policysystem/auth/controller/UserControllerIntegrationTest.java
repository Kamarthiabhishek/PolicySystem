package com.policysystem.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.policysystem.auth.dto.LoginRequest;
import com.policysystem.auth.dto.RegisterRequest;
import com.policysystem.auth.dto.UpdateRoleRequest;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.repository.RefreshTokenRepository;
import com.policysystem.auth.repository.UserRepository;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for UserController (admin endpoints).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("User Controller Integration Tests")
class UserControllerIntegrationTest {
    
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
    
    private String adminToken;
    private String customerToken;
    private Long adminId;
    private Long customerId;
    
    @BeforeEach
    @Transactional
    void setUp() throws Exception {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        
        // Create admin user
        User admin = User.builder()
                .name("Admin User")
                .email("admin@example.com")
                .passwordHash(passwordEncoder.encode("AdminPass123"))
                .role(Role.ADMIN)
                .build();
        admin = userRepository.save(admin);
        adminId = admin.getId();
        
        // Create customer user
        User customer = User.builder()
                .name("Customer User")
                .email("customer@example.com")
                .passwordHash(passwordEncoder.encode("CustomerPass123"))
                .role(Role.CUSTOMER)
                .build();
        customer = userRepository.save(customer);
        customerId = customer.getId();
        
        // Login as admin
        LoginRequest adminLogin = LoginRequest.builder()
                .email("admin@example.com")
                .password("AdminPass123")
                .build();
        
        MvcResult adminLoginResult = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(adminLogin)))
                .andExpect(status().isOk())
                .andReturn();
        
        com.policysystem.auth.dto.AuthResponse adminAuthResponse = objectMapper.readValue(
                adminLoginResult.getResponse().getContentAsString(),
                com.policysystem.auth.dto.AuthResponse.class
        );
        adminToken = adminAuthResponse.getAccessToken();
        
        // Login as customer
        LoginRequest customerLogin = LoginRequest.builder()
                .email("customer@example.com")
                .password("CustomerPass123")
                .build();
        
        MvcResult customerLoginResult = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(customerLogin)))
                .andExpect(status().isOk())
                .andReturn();
        
        com.policysystem.auth.dto.AuthResponse customerAuthResponse = objectMapper.readValue(
                customerLoginResult.getResponse().getContentAsString(),
                com.policysystem.auth.dto.AuthResponse.class
        );
        customerToken = customerAuthResponse.getAccessToken();
    }
    
    @Test
    @DisplayName("Admin should be able to list users")
    void testListUsers_AdminAccess() throws Exception {
        mockMvc.perform(get("/api/v1/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(2));
    }
    
    @Test
    @DisplayName("Customer should NOT be able to list users (403 Forbidden)")
    void testListUsers_CustomerAccessDenied() throws Exception {
        mockMvc.perform(get("/api/v1/users")
                .header("Authorization", "Bearer " + customerToken))
                .andExpect(status().isForbidden());
    }
    
    @Test
    @DisplayName("Unauthenticated user should NOT be able to list users (401)")
    void testListUsers_UnauthenticatedAccessDenied() throws Exception {
        mockMvc.perform(get("/api/v1/users"))
                .andExpect(status().isUnauthorized());
    }
    
    @Test
    @DisplayName("Admin should be able to change a user's role")
    void testUpdateUserRole_AdminAccess() throws Exception {
        UpdateRoleRequest request = UpdateRoleRequest.builder()
                .role("AGENT")
                .build();
        
        mockMvc.perform(patch("/api/v1/users/{id}/role", customerId)
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
        
        // Verify the role was actually changed
        User updatedUser = userRepository.findById(customerId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(Role.AGENT, updatedUser.getRole());
    }
    
    @Test
    @DisplayName("Customer should NOT be able to change a user's role (403)")
    void testUpdateUserRole_CustomerAccessDenied() throws Exception {
        UpdateRoleRequest request = UpdateRoleRequest.builder()
                .role("AGENT")
                .build();
        
        mockMvc.perform(patch("/api/v1/users/{id}/role", customerId)
                .header("Authorization", "Bearer " + customerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
    
    @Test
    @DisplayName("Admin should NOT be able to demote themselves as the only admin")
    void testUpdateUserRole_PreventSelfDemotion() throws Exception {
        UpdateRoleRequest request = UpdateRoleRequest.builder()
                .role("CUSTOMER")
                .build();
        
        mockMvc.perform(patch("/api/v1/users/{id}/role", adminId)
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("BAD_REQUEST"));
    }
    
    @Test
    @DisplayName("Admin can demote themselves if another admin exists")
    @Transactional
    void testUpdateUserRole_AllowDemotionWithMultipleAdmins() throws Exception {
        // Create another admin
        User secondAdmin = User.builder()
                .name("Second Admin")
                .email("admin2@example.com")
                .passwordHash(passwordEncoder.encode("AdminPass456"))
                .role(Role.ADMIN)
                .build();
        userRepository.save(secondAdmin);
        
        UpdateRoleRequest request = UpdateRoleRequest.builder()
                .role("AGENT")
                .build();
        
        mockMvc.perform(patch("/api/v1/users/{id}/role", adminId)
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
        
        // Verify the role was changed
        User updatedAdmin = userRepository.findById(adminId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(Role.AGENT, updatedAdmin.getRole());
    }
    
    @Test
    @DisplayName("Get current user should return authenticated user's profile")
    void testGetCurrentUser_Success() throws Exception {
        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer " + customerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(customerId))
                .andExpect(jsonPath("$.name").value("Customer User"))
                .andExpect(jsonPath("$.email").value("customer@example.com"))
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }
    
    @Test
    @DisplayName("Get current user without authentication should return 401")
    void testGetCurrentUser_Unauthenticated() throws Exception {
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized());
    }
}
