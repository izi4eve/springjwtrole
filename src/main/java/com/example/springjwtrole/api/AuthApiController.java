package com.example.springjwtrole.api;

import com.example.springjwtrole.dto.AuthRequest;
import com.example.springjwtrole.dto.AuthResponse;
import com.example.springjwtrole.dto.RegisterRequest;
import com.example.springjwtrole.security.JwtTokenProvider;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "${app.cors.origins}") // задаёшь в properties
public class AuthApiController {

    private final AuthenticationManager authManager;
    private final JwtTokenProvider tokenProvider;
    // Inject твой существующий UserService для регистрации
    // private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        String accessToken = tokenProvider.generateAccessToken(auth);
        String refreshToken = tokenProvider.generateRefreshToken(auth.getName());
        String role = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst().orElse("ROLE_USER");

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, auth.getName(), role));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }
        String username = tokenProvider.getUsernameFromToken(refreshToken);
        // Тут нужно загрузить UserDetails и создать новый accessToken
        // Упрощённо:
        String newRefresh = tokenProvider.generateRefreshToken(username);
        return ResponseEntity.ok(java.util.Map.of(
                "refreshToken", newRefresh
        ));
    }

    // @PostMapping("/register") — подключить твой существующий сервис
}