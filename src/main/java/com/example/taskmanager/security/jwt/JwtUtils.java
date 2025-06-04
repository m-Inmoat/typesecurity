package com.example.taskmanager.security.jwt;

import com.example.taskmanager.model.RefreshToken; // Corrected import path
import com.example.taskmanager.repository.RefreshTokenRepository;
import com.example.taskmanager.models.User; // User model path unchanged
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.services.UserDetailsImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie; // Added for getCleanJwtCookie, generateJwtCookie
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.WebUtils; // Added for getJwtFromCookies

import jakarta.servlet.http.Cookie; // Added for getJwtFromCookies
import jakarta.servlet.http.HttpServletRequest; // Added for getJwtFromCookies


import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${taskmanager.app.jwtSecret}")
    private String jwtSecret;

    @Value("${taskmanager.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${taskmanager.app.jwtCookieName}") // Assuming this property exists for cookie methods
    private String jwtCookie;

    @Value("${taskmanager.app.jwtRefreshExpirationMs}")
    private Long jwtRefreshExpirationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder().setSubject(username).setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }

    public RefreshToken createRefreshToken(Long userId) {
        RefreshToken refreshToken = new RefreshToken();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Error: User not found with id: " + userId));
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtRefreshExpirationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            // Consider throwing a custom exception that can be handled globally
            throw new RuntimeException("Refresh token " + token.getToken() + " was expired. Please make a new signin request.");
        }
        return token;
    }

    public boolean validateRefreshToken(String tokenString) {
         Optional<RefreshToken> refreshTokenOpt = findByToken(tokenString);
         if (refreshTokenOpt.isPresent()) {
             try {
                verifyExpiration(refreshTokenOpt.get());
                return true;
             } catch (RuntimeException e) { // Catch the specific exception from verifyExpiration
                 logger.error("Refresh token expired or invalid: {}", e.getMessage());
                 return false;
             }
         }
         logger.warn("Refresh token string not found in DB: {}", tokenString);
         return false;
    }

    public String getUsernameFromRefreshToken(String tokenString) {
        RefreshToken refreshToken = findByToken(tokenString)
            .orElseThrow(() -> new RuntimeException("Refresh token not found in database: " + tokenString));
        // verifyExpiration will throw an exception if it's expired, which is good.
        verifyExpiration(refreshToken);
        return refreshToken.getUser().getUsername();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    // Methods that were in AuthController and likely belong in JwtUtils for cookie handling
    // generateJwtCookie, getJwtFromCookies, getCleanJwtCookie

    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        return ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
    }

    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookie, null).path("/api").build();
    }
}
