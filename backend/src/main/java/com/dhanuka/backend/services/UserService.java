package com.dhanuka.backend.services;

import com.dhanuka.backend.dtos.CredentialsDto;
import com.dhanuka.backend.dtos.SignUpDto;
import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.entities.Session;
import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.repositories.SessionRepository;
import com.dhanuka.backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;

    @Transactional
    public UserDto login(CredentialsDto credentialsDto, String ipAddress, String userAgent) {
        String email = credentialsDto.getEmail();
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));

        if (!user.getPasswordHash().equals(credentialsDto.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }

        String refreshToken = UUID.randomUUID().toString();
        Session session = Session.builder()
                .user(user)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiredAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .build();
        sessionRepository.save(session);

        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .isEmailVerified(user.isEmailVerified())
                .token(refreshToken)
                .build();
    }

    @Transactional
    public UserDto register(SignUpDto signUpDto, String ipAddress, String userAgent) {
        String email = signUpDto.getEmail();
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already registered");
        }

        User user = User.builder()
                .email(email)
                .passwordHash(signUpDto.getPassword())
                .isEmailVerified(false)
                .build();

        User savedUser = userRepository.save(user);

        String refreshToken = UUID.randomUUID().toString();
        Session session = Session.builder()
                .user(savedUser)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiredAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .build();
        sessionRepository.save(session);

        return UserDto.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .isEmailVerified(savedUser.isEmailVerified())
                .token(refreshToken)
                .build();
    }

    public UserDto findByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .isEmailVerified(user.isEmailVerified())
                .build();
    }
}
