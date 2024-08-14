package com.example.springjwtrole.controller;

import com.example.springjwtrole.model.Role;
import com.example.springjwtrole.model.User;
import com.example.springjwtrole.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.validation.Valid;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute("user") User user, BindingResult result) {
        if (result.hasErrors()) {
            return "register";
        }
        user.setRole(Role.REGISTERED);
        userService.save(user);
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        return "login";
    }

    @GetMapping("/account")
    public String account(Model model, Principal principal) {
        // Получаем email пользователя из Principal
        String email = principal.getName();

        // Находим пользователя в базе данных
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // Добавляем данные пользователя в модель
        model.addAttribute("user", user);

        return "account";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:/"; // Логика для выхода из системы уже настроена в SecurityConfig
    }
}