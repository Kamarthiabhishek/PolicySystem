package com.policysystem.auth.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Standard error response shape for all module responses.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ErrorResponse {
    
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("status")
    private int status;
    
    @JsonProperty("error")
    private String error;
    
    @JsonProperty("message")
    private String message;
    
    @JsonProperty("fieldErrors")
    private List<FieldError> fieldErrors;
    
    /**
     * FieldError for validation errors.
     */
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class FieldError {
        
        @JsonProperty("field")
        private String field;
        
        @JsonProperty("message")
        private String message;
    }
}
