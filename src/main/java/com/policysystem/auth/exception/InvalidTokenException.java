package com.policysystem.auth.exception;

/**
 * Exception thrown when a refresh token is invalid, expired, or revoked.
 */
public class InvalidTokenException extends RuntimeException {
    
    public InvalidTokenException(String message) {
        super(message);
    }
    
    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
