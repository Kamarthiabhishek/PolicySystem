package com.policysystem.auth.repository;

import com.policysystem.auth.entity.Role;
import com.policysystem.auth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for User entity operations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * Find a user by email (case-insensitive).
     */
    Optional<User> findByEmailIgnoreCase(String email);
    
    /**
     * Check if a user exists with the given email (case-insensitive).
     */
    boolean existsByEmailIgnoreCase(String email);
    
    /**
     * Count the number of users with a specific role.
     */
    long countByRole(Role role);
    
    /**
     * Find users by role with pagination support.
     */
    Page<User> findByRole(Role role, Pageable pageable);
}
