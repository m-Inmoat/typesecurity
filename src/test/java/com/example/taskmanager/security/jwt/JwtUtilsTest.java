package com.example.taskmanager.security.jwt;

import com.example.taskmanager.model.RefreshToken;
import com.example.taskmanager.model.User;
import com.example.taskmanager.repository.RefreshTokenRepository;
import com.example.taskmanager.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtUtilsTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private JwtUtils jwtUtils;

    private User testUser;
    private RefreshToken testRefreshToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtils, "jwtRefreshExpirationMs", 3600000L); // 1 hour
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", "testSecret");
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 60000);


        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        // Assuming User model has email and password setters if needed by other tests, not strictly for these.
        // testUser.setEmail("test@example.com");
        // testUser.setPassword("password");


        testRefreshToken = new RefreshToken();
        testRefreshToken.setToken(UUID.randomUUID().toString());
        testRefreshToken.setUser(testUser);
        testRefreshToken.setExpiryDate(Instant.now().plusMillis(3600000L)); // Expires in 1 hour
    }

    @Test
    void createRefreshToken_shouldCreateAndSaveToken() {
        when(userRepository.findById(anyLong())).thenReturn(Optional.of(testUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RefreshToken createdToken = jwtUtils.createRefreshToken(testUser.getId());

        assertNotNull(createdToken.getToken());
        assertEquals(testUser.getId(), createdToken.getUser().getId());
        assertTrue(createdToken.getExpiryDate().isAfter(Instant.now()));
        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    }

    @Test
    void validateRefreshToken_validToken_shouldReturnTrue() {
        when(refreshTokenRepository.findByToken(testRefreshToken.getToken())).thenReturn(Optional.of(testRefreshToken));

        assertTrue(jwtUtils.validateRefreshToken(testRefreshToken.getToken()));
    }

    @Test
    void validateRefreshToken_expiredToken_shouldReturnFalseAndDelete() {
        testRefreshToken.setExpiryDate(Instant.now().minusMillis(1000)); // Expired
        when(refreshTokenRepository.findByToken(testRefreshToken.getToken())).thenReturn(Optional.of(testRefreshToken));

        assertFalse(jwtUtils.validateRefreshToken(testRefreshToken.getToken()));
        verify(refreshTokenRepository, times(1)).delete(testRefreshToken);
    }

    @Test
    void validateRefreshToken_nonExistentToken_shouldReturnFalse() {
        when(refreshTokenRepository.findByToken("nonexistent")).thenReturn(Optional.empty());
        assertFalse(jwtUtils.validateRefreshToken("nonexistent"));
    }


    @Test
    void getUsernameFromRefreshToken_validToken_shouldReturnUsername() {
        when(refreshTokenRepository.findByToken(testRefreshToken.getToken())).thenReturn(Optional.of(testRefreshToken));

        String username = jwtUtils.getUsernameFromRefreshToken(testRefreshToken.getToken());
        assertEquals(testUser.getUsername(), username);
    }

    @Test
    void getUsernameFromRefreshToken_expiredToken_shouldThrowException() {
        testRefreshToken.setExpiryDate(Instant.now().minusMillis(1000)); // Expired
        when(refreshTokenRepository.findByToken(testRefreshToken.getToken())).thenReturn(Optional.of(testRefreshToken));

        Exception exception = assertThrows(RuntimeException.class, () -> {
            jwtUtils.getUsernameFromRefreshToken(testRefreshToken.getToken());
        });
        assertTrue(exception.getMessage().contains("was expired"));
        verify(refreshTokenRepository, times(1)).delete(testRefreshToken); // verify delete is called by verifyExpiration
    }

    @Test
    void getUsernameFromRefreshToken_nonExistentToken_shouldThrowException() {
        when(refreshTokenRepository.findByToken("nonexistent")).thenReturn(Optional.empty());
         Exception exception = assertThrows(RuntimeException.class, () -> {
            jwtUtils.getUsernameFromRefreshToken("nonexistent");
        });
        assertTrue(exception.getMessage().contains("not found in database"));
    }
}
