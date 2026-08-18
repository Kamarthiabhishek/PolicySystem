package com.policysystem.auth.service;

import com.policysystem.auth.dto.UserResponse;
import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import com.policysystem.auth.exception.DuplicateEmailException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * UserService handles user management operations: registration, profile access, role changes.
 * Enforces security rules like email uniqueness and admin self-demotion guards.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {
    
    private final com.policysystem.auth.repository.UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Register a new user with email and password.
     * 
     * @param name the user's full name
     * @param email the user's email (must be unique)
     * @param password the plaintext password
     * @return the created UserResponse
     * @throws DuplicateEmailException if email is already registered
     */
    public UserResponse register(String name, String email, String password) {
        // Check email uniqueness (case-insensitive)
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new DuplicateEmailException("Email already registered");
        }
        
        // Create new user with default role CUSTOMER
        User user = User.builder()
                .name(name)
                .email(email.toLowerCase())
                .passwordHash(passwordEncoder.encode(password))
                .role(Role.CUSTOMER)
                .build();
        
        User savedUser = userRepository.save(user);
        return UserResponse.fromUser(savedUser);
    }
    
    /**
     * Get a user by ID.
     * 
     * @param userId the user's ID
     * @return the User entity
     */
    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }
    
    /**
     * Get the current user's profile.
     * 
     * @param userId the authenticated user's ID
     * @return UserResponse with profile information
     */
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(Long userId) {
        User user = getUserById(userId);
        return UserResponse.fromUser(user);
    }
    
    /**
     * List all users with optional filtering by role.
     * 
     * @param pageable pagination info
     * @param role optional role filter
     * @return paginated list of users
     */
    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(Pageable pageable, Role role) {
        Page<User> users;
        if (role != null) {
            users = userRepository.findByRole(role, pageable);
        } else {
            users = userRepository.findAll(pageable);
        }
        return users.map(UserResponse::fromUser);
    }
    
    /**
     * Change a user's role (admin operation).
     * Guards against admin self-demotion: if the admin is the only admin, they cannot demote themselves.
     * 
     * @param userId the user to update
     * @param newRole the new role
     * @param adminUserId the admin performing the action
     * @throws IllegalArgumentException if admin tries to demote themselves as the only admin
     */
    public void changeUserRole(Long userId, Role newRole, Long adminUserId) {
        User user = getUserById(userId);
        
        // Guard against admin self-demotion
        if (userId.equals(adminUserId) && newRole != Role.ADMIN && user.getRole() == Role.ADMIN) {
            long adminCount = userRepository.countByRole(Role.ADMIN);
            if (adminCount == 1) {
                throw new IllegalArgumentException(
                        "Cannot demote the last remaining admin"
                );
            }
        }
        
        user.setRole(newRole);
        userRepository.save(user);
    }
}
