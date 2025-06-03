package com.example.taskmanager.controller;

import com.example.taskmanager.payload.request.RefreshTokenRequest;
// import com.example.taskmanager.payload.response.NewAccessTokenResponse; // Not directly used in asserts, jsonPath is used
import com.example.taskmanager.repository.RoleRepository;
import com.example.taskmanager.repository.UserRepository;
import com.example.taskmanager.security.jwt.JwtUtils;
import com.example.taskmanager.security.services.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private AuthenticationManager authenticationManager; // Often needed for @WebMvcTest on AuthController

    @MockBean
    private UserRepository userRepository; // Mocked due to AuthController autowiring it

    @MockBean
    private RoleRepository roleRepository; // Mocked due to AuthController autowiring it

    @MockBean
    private PasswordEncoder passwordEncoder; // Mocked due to AuthController autowiring it

    @MockBean
    private UserDetailsServiceImpl userDetailsService; // Required by WebSecurityConfig which is auto-configured

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void refreshToken_validToken_shouldReturnNewAccessToken() throws Exception {
        String oldRefreshToken = "valid-refresh-token";
        String newAccessToken = "new-access-token";
        String username = "testuser";

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken(oldRefreshToken);

        when(jwtUtils.validateRefreshToken(oldRefreshToken)).thenReturn(true);
        when(jwtUtils.getUsernameFromRefreshToken(oldRefreshToken)).thenReturn(username);
        when(jwtUtils.generateTokenFromUsername(username)).thenReturn(newAccessToken);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(newAccessToken))
                .andExpect(jsonPath("$.tokenType").value("Bearer")); // As NewAccessTokenResponse has this default
    }

    @Test
    void refreshToken_invalidToken_shouldReturnUnauthorized() throws Exception {
        String invalidRefreshToken = "invalid-refresh-token";
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken(invalidRefreshToken);

        when(jwtUtils.validateRefreshToken(invalidRefreshToken)).thenReturn(false);

        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshTokenRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Error: Invalid refresh token!"));
    }
}
