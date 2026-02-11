package com.shynecrm.backend.controller;

import com.shynecrm.backend.dto.AuthResponse;
import com.shynecrm.backend.dto.LoginRequest;
import com.shynecrm.backend.dto.RegisterRequest;
import com.shynecrm.backend.model.User;
import com.shynecrm.backend.repository.UserRepository;
import com.shynecrm.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        String token = authService.register(
                request.getEmail(),
                request.getPassword(),
                request.getFirstName(),
                request.getLastName()
        );

        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow();

        AuthResponse response = new AuthResponse(
                token,
                user.getEmail(),
                user.getFirstName(),
                user.getRole().name()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        String token = authService.login(
                request.getEmail(),
                request.getPassword()
        );

        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow();

        AuthResponse response = new AuthResponse(
                token,
                user.getEmail(),
                user.getFirstName(),
                user.getRole().name()
        );

        return ResponseEntity.ok(response);
    }
}
