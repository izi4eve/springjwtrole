package com.example.springjwtrole.service;

import com.example.springjwtrole.model.User;
import com.example.springjwtrole.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserCleanupService {

    private final UserRepository userRepository;

    @Transactional
//    @Scheduled(cron = "0 0 * * * *")  // Запуск каждый час
    @Scheduled(cron = "0 0 0 * * *")  // <<<<<<< Раз в день в 0 часов
//    @Scheduled(cron = "0 0 3 * * *")  // Раз в день в 3 часа утра
//    @Scheduled(cron = "0 0 0 * * MON")   // Раз в неделю в полночь понедельника
//    @Scheduled(cron = "0 0 12 * * SUN")  // Раз в неделю в полдень воскресенья
    public void removeUnconfirmedUsers() {
        LocalDateTime threshold = LocalDateTime.now().minusHours(24);
//        LocalDateTime threshold = LocalDateTime.now().minusHours(1);
        List<User> usersToDelete = userRepository.findByEnabledFalseAndCreatedAtBefore(threshold);

        for (User user : usersToDelete) {
            userRepository.delete(user);
        }
    }

    @Transactional
    public void removeUnconfirmedUsersManually() {
        removeUnconfirmedUsers();
    }
}