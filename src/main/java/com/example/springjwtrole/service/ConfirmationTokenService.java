package com.example.springjwtrole.service;

import com.example.springjwtrole.model.ConfirmationToken;
import com.example.springjwtrole.model.User;
import com.example.springjwtrole.repository.ConfirmationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ConfirmationToken createToken(User user) {
        ConfirmationToken token = new ConfirmationToken();
        token.setToken(UUID.randomUUID().toString());
        token.setCreatedAt(LocalDateTime.now());
        token.setExpiresAt(LocalDateTime.now().plusHours(24));  // Токен действует 24 часа
        token.setUser(user);
        return confirmationTokenRepository.save(token);
    }

    public ConfirmationToken validateToken(String token) {
        return confirmationTokenRepository.findByToken(token)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .orElseThrow(() -> new IllegalArgumentException("Неверный или истекший токен."));
    }

    public void deleteToken(ConfirmationToken token) {
        confirmationTokenRepository.delete(token);
    }

    public void saveToken(ConfirmationToken token) {
        confirmationTokenRepository.save(token);
    }
}