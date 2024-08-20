package com.example.springjwtrole.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    REGISTERED,
    MODERATOR,
    ADMIN,
    BLOCKED;

    @Override
    public String getAuthority() {
        return "ROLE_" + name(); // Используем префикс "ROLE_" для соответствия требованиям Spring Security
    }
}