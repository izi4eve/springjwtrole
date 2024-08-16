package com.example.springjwtrole.controller;

import com.example.springjwtrole.service.UserCleanupService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserCleanupService userCleanupService;

    @PostMapping("/cleanup-users")
    public String cleanupUsers() {
        userCleanupService.removeUnconfirmedUsersManually();
        return "Очистка неактивированных пользователей выполнена.";
    }
}