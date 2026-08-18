package com.policysystem.auth.exception;

/**
 * Exception thrown when an email is already registered.
 */
public class DuplicateEmailException extends RuntimeException {
    
    public DuplicateEmailException(String message) {
        super(message);
    }
    
    public DuplicateEmailException(String message, Throwable cause) {
        super(message, cause);
    }
}
