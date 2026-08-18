package com.policysystem.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility for hashing refresh tokens.
 * Uses SHA-256 for deterministic hashing (unlike BCrypt which generates different hashes each time).
 * This allows us to look up tokens by their hash in the database.
 */
public class TokenHasher {
    
    private static final String ALGORITHM = "SHA-256";
    
    /**
     * Hash a token using SHA-256.
     * 
     * @param token the token to hash
     * @return base64-encoded SHA-256 hash
     */
    public static String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
