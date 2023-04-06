package com.example.gatewayservice.security.jwt;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private String extractTokenFromHeader(String token) {
        return token.substring(7);
    }

    public boolean validateToken(final String token) {
        try {
            String extractedToken = extractTokenFromHeader(token);
            Jwts.parser().setSigningKey(secret).parseClaimsJws(extractedToken);
        } catch (UnsupportedJwtException exception) {
            log.error("the claimsJws argument does not represent an Claims JWS", exception);
            return false;
        } catch (MalformedJwtException exception) {
            log.error("Invalid token provided", exception);
            return false;
        } catch (SignatureException exception) {
            log.error("Invalid signature", exception);
            return false;
        } catch (ExpiredJwtException exception) {
            log.error("Token has expired", exception);
            return false;
        } catch (IllegalArgumentException exception) {
            log.error("the claimsJws string is null or empty or only whitespace", exception);
            return false;
        }
        return true;
    }
}