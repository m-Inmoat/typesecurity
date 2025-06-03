package com.example.taskmanager.repository;

import com.example.taskmanager.model.RefreshToken; // Corrected import path
import com.example.taskmanager.models.User; // User model path unchanged as per current instructions
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    int deleteByUser(User user);
}
