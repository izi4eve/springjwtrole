package com.example.springjwtrole.service;

import com.example.springjwtrole.model.ConfirmationToken;
import com.example.springjwtrole.model.User;
import com.example.springjwtrole.repository.ConfirmationTokenRepository;
import com.example.springjwtrole.util.MessageUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final MessageUtil messageUtil;

    public ConfirmationToken createToken(User user) {
        ConfirmationToken token = new ConfirmationToken();
        token.setToken(UUID.randomUUID().toString());
        token.setCreatedAt(LocalDateTime.now());
        token.setExpiresAt(LocalDateTime.now().plusHours(24));  // token is valid for 24 hours
        token.setUser(user);
        return confirmationTokenRepository.save(token);
    }

    public ConfirmationToken validateToken(String token, String lang) {
        return confirmationTokenRepository.findByToken(token)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .orElseThrow(() -> new IllegalArgumentException(messageUtil.getMessage("token.invalidOrExpired", lang)));
    }

    public void deleteToken(ConfirmationToken token) {
        confirmationTokenRepository.delete(token);
    }

    public void saveToken(ConfirmationToken token) {
        confirmationTokenRepository.save(token);
    }
}