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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.core.Authentication;
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
    public String registerUser(@Valid @ModelAttribute("user") User user, BindingResult result, Model model) {
        if (result.hasErrors()) {
            return "register";
        }

        if (userService.findByEmail(user.getEmail()).isPresent()) {
            model.addAttribute("emailError", "Пользователь с таким email уже зарегистрирован.");
            return "register";
        }

        user.setRole(Role.REGISTERED);
        userService.save(user);
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String showLoginForm(@RequestParam(value = "error", required = false) String error, Model model, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/account";
        }

        if (error != null) {
            model.addAttribute("loginError", "Неправильный email или пароль.");
        }
        return "login";
    }

    @GetMapping("/account")
    public String account(Model model, Principal principal) {
        String email = principal.getName();
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        model.addAttribute("user", user);
        return "account";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:/"; // Логика для выхода из системы уже настроена в SecurityConfig
    }
}