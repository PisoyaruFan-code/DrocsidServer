package psf.server.drocsidserver.Services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtUtil {
    private static Key key = null;

    public JwtUtil() {
        key = Keys.hmacShaKeyFor("e3f1a7c9b4d28e5f6a1c3d7f8b9e0a2c4d6f7b8e9a1c2d3e4f5a6b7c8d9e0f1".getBytes());
    }
    public static String generateToken(String subject, long expirationTimeInMinutes) {
        long expirationTimeInMillis = expirationTimeInMinutes * 60 * 1000;
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationTimeInMillis)) // 10 hours
                .signWith(key)
                .compact();
    }
    public static String extractSubject(String token) {
        return extractClaims(token).getSubject();
    }
    public static boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }
    public static boolean validateToken(String token, String username) {
        return (username.equals(extractSubject(token)) && !isTokenExpired(token));
    }
    private static Claims extractClaims(String token) {
        return Jwts.parser()
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
