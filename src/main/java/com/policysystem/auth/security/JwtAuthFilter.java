package com.policysystem.auth.security;

import com.policysystem.auth.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthFilter extracts and validates JWT tokens from the Authorization header.
 * On successful validation, loads user details and sets the SecurityContext.
 * This filter runs once per request to extract JWT claims and populate Spring Security context.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        try {
            String token = extractTokenFromHeader(request);
            
            if (token != null) {
                // Validate token signature and expiry
                if (jwtTokenProvider.validateToken(token)) {
                    Long userId = jwtTokenProvider.getUserIdFromToken(token);
                    String email = jwtTokenProvider.getEmailFromToken(token);
                    
                    // Load user from database to get UserDetails
                    UserDetails userDetails = userRepository.findById(userId)
                            .orElseThrow(() -> new IllegalArgumentException("User not found"));
                    
                    // Create authentication token
                    UsernamePasswordAuthenticationToken auth = 
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );
                    
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    
                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    
                    log.debug("JWT token validated for user: {}", email);
                }
            }
        } catch (JwtException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("User not found for JWT token: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Error processing JWT token", e);
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Extract JWT token from the Authorization header.
     * Expected format: "Bearer <token>"
     * 
     * @param request the HTTP request
     * @return the JWT token, or null if not present/invalid format
     */
    private String extractTokenFromHeader(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}
