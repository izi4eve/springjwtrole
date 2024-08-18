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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.Optional;

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
    public String registerUser(@Valid @ModelAttribute("user") User user, BindingResult result, Model model, RedirectAttributes redirectAttributes) {
        if (result.hasErrors()) {
            return "register";
        }

        if (userService.findByEmail(user.getEmail()).isPresent()) {
            model.addAttribute("emailError", "Пользователь с таким email уже зарегистрирован.");
            return "register";
        }

        user.setRole(Role.REGISTERED);
        userService.save(user);

        redirectAttributes.addFlashAttribute("registrationSuccess", "Спасибо за регистрацию! Проверьте свою почту для подтверждения.");
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String showLoginForm(@RequestParam(value = "error", required = false) String error, Model model, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/account";
        }

        if (error != null) {
            String email = (String) model.asMap().get("username");
            Optional<User> user = userService.findByEmail(email);
            if (user.isPresent() && !user.get().isEnabled()) {
                model.addAttribute("loginError", "Вы ещё не подтвердили свою почту.");
            } else {
                model.addAttribute("loginError", "Неправильный email, пароль или вы ещё не подтвердили свой аккаунт по почте.");
            }
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

    @GetMapping("/confirm")
    public String confirmUser(@RequestParam("token") String token, Model model) {
        try {
            userService.confirmUser(token);
            model.addAttribute("confirmationMessage", "Почта успешно подтверждена. Теперь вы можете войти в свой аккаунт.");
            return "login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("confirmationMessage", "Неверный токен.");
            return "login";
        } catch (IllegalStateException e) {
            model.addAttribute("confirmationMessage", "Аккаунт уже подтвержден.");
            return "login";
        }
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String handleForgotPassword(@RequestParam("email") String email, Model model) {
        Optional<User> userOptional = userService.findByEmail(email);

        if (userOptional.isPresent()) {
            userService.sendPasswordResetEmail(userOptional.get());
            model.addAttribute("message", "Письмо с инструкциями по восстановлению пароля отправлено на вашу почту.");
        } else {
            model.addAttribute("error", "Пользователь с таким email не найден.");
        }

        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
        if (!userService.isPasswordResetTokenValid(token)) {
            model.addAttribute("error", "Неверный или истёкший токен.");
            return "forgot-password";
        }
        model.addAttribute("token", token);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(
            @RequestParam("token") String token,
            @RequestParam("password") String password,
            @RequestParam("confirmPassword") String confirmPassword,
            Model model,
            RedirectAttributes redirectAttributes) {

        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Пароли не совпадают.");
            return "reset-password";
        }

        try {
            userService.resetPassword(token, password);
            redirectAttributes.addFlashAttribute("message", "Пароль успешно изменён.");
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", "Неверный или истёкший токен.");
            return "reset-password";
        }
    }

}