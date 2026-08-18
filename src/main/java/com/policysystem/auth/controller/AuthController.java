package com.policysystem.auth.controller;

import com.policysystem.auth.dto.AuthResponse;
import com.policysystem.auth.dto.LoginRequest;
import com.policysystem.auth.dto.RefreshRequest;
import com.policysystem.auth.dto.RegisterRequest;
import com.policysystem.auth.dto.UserResponse;
import com.policysystem.auth.service.AuthService;
import com.policysystem.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AuthController handles authentication endpoints: register, login, and refresh token.
 * All endpoints are public (no authentication required).
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final UserService userService;
    
    /**
     * POST /api/v1/auth/register
     * Register a new user with email and password.
     * Role is always set to CUSTOMER (never accepted from client).
     * 
     * @param request the registration request
     * @return 201 Created with UserResponse
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse userResponse = userService.register(
                request.getName(),
                request.getEmail(),
                request.getPassword()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
    }
    
    /**
     * POST /api/v1/auth/login
     * Authenticate a user and return access + refresh tokens.
     * Returns generic "Invalid credentials" for both user-not-found and wrong-password cases.
     * 
     * @param request the login request
     * @return 200 OK with AuthResponse containing tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(authResponse);
    }
    
    /**
     * POST /api/v1/auth/refresh
     * Refresh an access token using a refresh token.
     * Implements token rotation: old refresh token is invalidated, new one issued.
     * 
     * @param request the refresh request containing the refresh token
     * @return 200 OK with new AuthResponse containing new tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        AuthResponse authResponse = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(authResponse);
    }
}
