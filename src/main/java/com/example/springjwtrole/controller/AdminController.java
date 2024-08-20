package com.example.springjwtrole.controller;

import com.example.springjwtrole.model.Role;
import com.example.springjwtrole.model.User;
import com.example.springjwtrole.repository.UserRepository;
import com.example.springjwtrole.service.UserCleanupService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserCleanupService userCleanupService;
    private final UserRepository userRepository;

    @GetMapping("/set-role")
    public String showRoleForm(Model model) {
        model.addAttribute("roles", Role.values());  // Передаём список ролей в модель
        return "set-role";
    }

    @PostMapping("/set-role")
    public String setRole(@RequestParam String email, @RequestParam String role, Model model) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("Пользователь с таким email не найден"));

            user.setRole(Role.valueOf(role.toUpperCase()));
            userRepository.save(user);

            model.addAttribute("message", "Роль пользователя " + email + " обновлена до " + role);
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
        }

        model.addAttribute("roles", Role.values());  // Передаём список ролей обратно в модель
        return "set-role";
    }

    @GetMapping("/cleanup-users")
    public String cleanupUsers(RedirectAttributes redirectAttributes) {
        userCleanupService.removeUnconfirmedUsersManually();
        redirectAttributes.addFlashAttribute("message", "Очистка неактивированных пользователей выполнена успешно.");
        return "redirect:/account"; // Перенаправляем на /account
    }
}