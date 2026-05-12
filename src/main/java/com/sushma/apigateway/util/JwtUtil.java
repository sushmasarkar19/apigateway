package com.sushma.apigateway.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/**
 * JWT utility for the API Gateway.
 *
 * Uses the SAME secret as olx-login (jwt.secret=sushg12) so the gateway
 * can validate tokens locally without calling olx-login for every request.
 * This avoids an extra network hop and keeps the gateway self-contained.
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretString;

    private Key signingKey;

    @PostConstruct
    public void init() {
        // Pad secret to 32 bytes (256 bits) – required for HS256
        byte[] keyBytes = secretString.getBytes();
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, keyBytes.length);
            signingKey = Keys.hmacShaKeyFor(padded);
        } else {
            signingKey = Keys.hmacShaKeyFor(keyBytes);
        }
    }

    /**
     * Validates the token: checks signature, expiry.
     * Returns true if valid, false otherwise.
     */
    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Extracts the username (subject) from a valid token.
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Returns true if the token is expired.
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiry = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getExpiration();
            return expiry.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
}