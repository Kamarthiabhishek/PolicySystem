package com.policysystem.security;

import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Date;

public class JwtUtil {

    private final String SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    public String generateToken(UserDetails userDetails) {

        Instant now = Instant.now();

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis()))
    }
}
