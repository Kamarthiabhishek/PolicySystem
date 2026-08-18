package com.policysystem.auth.service;

import com.policysystem.auth.dto.UserResponse;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.exception.DuplicateEmailException;
import com.policysystem.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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
 * Unit tests for UserService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Unit Tests")
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    private PasswordEncoder passwordEncoder;
    private UserService userService;
    
    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(10);
        userService = new UserService(userRepository, passwordEncoder);
    }
    
    @Test
    @DisplayName("Should register a new user successfully")
    void testRegister_Success() {
        String name = "John Doe";
        String email = "john@example.com";
        String password = "SecurePass123";
        
        when(userRepository.existsByEmailIgnoreCase(email)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(1L);
            return user;
        });
        
        UserResponse response = userService.register(name, email, password);
        
        assertNotNull(response);
        assertEquals(1L, response.getId());
        assertEquals(name, response.getName());
        assertEquals(email, response.getEmail());
        assertEquals("CUSTOMER", response.getRole());
        
        // Verify the user was saved with correct data
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertEquals(name, savedUser.getName());
        assertEquals(email.toLowerCase(), savedUser.getEmail());
        assertEquals(Role.CUSTOMER, savedUser.getRole());
        // Verify password was hashed (not stored as plain text)
        assertNotEquals(password, savedUser.getPasswordHash());
        assertTrue(passwordEncoder.matches(password, savedUser.getPasswordHash()));
    }
    
    @Test
    @DisplayName("Should reject duplicate email during registration")
    void testRegister_DuplicateEmail() {
        String email = "existing@example.com";
        
        when(userRepository.existsByEmailIgnoreCase(email)).thenReturn(true);
        
        assertThrows(DuplicateEmailException.class, () ->
                userService.register("Jane Doe", email, "SecurePass123")
        );
        
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Should get user by ID successfully")
    void testGetUserById_Success() {
        User mockUser = User.builder()
                .id(1L)
                .name("John Doe")
                .email("john@example.com")
                .role(Role.CUSTOMER)
                .build();
        
        when(userRepository.findById(1L)).thenReturn(Optional.of(mockUser));
        
        User user = userService.getUserById(1L);
        
        assertNotNull(user);
        assertEquals(1L, user.getId());
        assertEquals("John Doe", user.getName());
    }
    
    @Test
    @DisplayName("Should throw exception when user not found by ID")
    void testGetUserById_NotFound() {
        when(userRepository.findById(999L)).thenReturn(Optional.empty());
        
        assertThrows(IllegalArgumentException.class, () ->
                userService.getUserById(999L)
        );
    }
    
    @Test
    @DisplayName("Should get current user profile")
    void testGetCurrentUser_Success() {
        User mockUser = User.builder()
                .id(1L)
                .name("John Doe")
                .email("john@example.com")
                .role(Role.AGENT)
                .build();
        
        when(userRepository.findById(1L)).thenReturn(Optional.of(mockUser));
        
        UserResponse response = userService.getCurrentUser(1L);
        
        assertNotNull(response);
        assertEquals(1L, response.getId());
        assertEquals("John Doe", response.getName());
        assertEquals("john@example.com", response.getEmail());
        assertEquals("AGENT", response.getRole());
    }
    
    @Test
    @DisplayName("Should prevent admin self-demotion when last admin")
    void testChangeUserRole_PreventSelfDemotion() {
        User adminUser = User.builder()
                .id(1L)
                .name("Admin User")
                .email("admin@example.com")
                .role(Role.ADMIN)
                .build();
        
        when(userRepository.findById(1L)).thenReturn(Optional.of(adminUser));
        when(userRepository.countByRole(Role.ADMIN)).thenReturn(1L);
        
        // Attempting to demote themselves as the only admin
        assertThrows(IllegalArgumentException.class, () ->
                userService.changeUserRole(1L, Role.CUSTOMER, 1L)
        );
        
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Should allow admin demotion when multiple admins exist")
    void testChangeUserRole_DemotionWithMultipleAdmins() {
        User adminUser = User.builder()
                .id(1L)
                .name("Admin User")
                .email("admin@example.com")
                .role(Role.ADMIN)
                .build();
        
        when(userRepository.findById(1L)).thenReturn(Optional.of(adminUser));
        when(userRepository.countByRole(Role.ADMIN)).thenReturn(2L);
        when(userRepository.save(any(User.class))).thenReturn(adminUser);
        
        userService.changeUserRole(1L, Role.CUSTOMER, 1L);
        
        assertEquals(Role.CUSTOMER, adminUser.getRole());
        verify(userRepository).save(adminUser);
    }
    
    @Test
    @DisplayName("Should allow role change by different admin")
    void testChangeUserRole_ByDifferentAdmin() {
        User targetUser = User.builder()
                .id(2L)
                .name("User")
                .email("user@example.com")
                .role(Role.CUSTOMER)
                .build();
        
        when(userRepository.findById(2L)).thenReturn(Optional.of(targetUser));
        when(userRepository.save(any(User.class))).thenReturn(targetUser);
        
        userService.changeUserRole(2L, Role.AGENT, 1L);
        
        assertEquals(Role.AGENT, targetUser.getRole());
        verify(userRepository).save(targetUser);
    }
}
