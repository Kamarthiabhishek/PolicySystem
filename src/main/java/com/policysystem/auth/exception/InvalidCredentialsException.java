package com.policysystem.auth.exception;

/**
 * Exception thrown when login credentials are invalid.
 * This is a generic exception used for both "user not found" and "wrong password" cases
 * to avoid revealing which part of the credentials was incorrect.
 */
public class InvalidCredentialsException extends RuntimeException {
    
    public InvalidCredentialsException(String message) {
        super(message);
    }
    
    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}
