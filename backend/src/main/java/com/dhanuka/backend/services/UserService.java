package com.dhanuka.backend.services;

import com.dhanuka.backend.dtos.CredentialsDto;
import com.dhanuka.backend.dtos.SignUpDto;
import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.entities.Session;
import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.repositories.PasswordResetRepository;
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
    private final PasswordResetRepository passwordResetRepository;
    private final EmailService emailService;

    @org.springframework.beans.factory.annotation.Value("${app.frontend.url:http://localhost:4200}")
    private String frontendUrl;

    @Transactional
    public UserDto login(CredentialsDto credentialsDto, String ipAddress, String userAgent) {
        String email = credentialsDto.getEmail();
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));

        if (!org.mindrot.jbcrypt.BCrypt.checkpw(credentialsDto.getPassword(), user.getPasswordHash())) {
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

        if (!email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email format");
        }

        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already registered");
        }

        String password = signUpDto.getPassword();
        if (password == null || password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
        }

        if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,15}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be 8-15 characters long, and include at least one uppercase letter, one lowercase letter, one number, and one special character (@#$%^&+=!)");
        }

        String confirmPassword = signUpDto.getConfirmPassword();
        if (confirmPassword == null || !confirmPassword.equals(password)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passwords do not match");
        }

        User user = User.builder()
                .email(email)
                .passwordHash(org.mindrot.jbcrypt.BCrypt.hashpw(signUpDto.getPassword(), org.mindrot.jbcrypt.BCrypt.gensalt()))
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

    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User with this email does not exist"));

        String token = UUID.randomUUID().toString();
        // Here we just store the token directly or a hash. Since this is an example, we can store it directly.
        // It's better to store a hash, but for simplicity of reset, we'll store the token itself in tokenHash for now.
        // If we store hash, we need the raw token in email. Let's just store raw token for ease, or hash it.
        // The entity field is named `tokenHash` though. So let's just store the raw token in `tokenHash` field for simplicity.
        // Wait, standard practice is to hash it.
        String hashedToken = org.mindrot.jbcrypt.BCrypt.hashpw(token, org.mindrot.jbcrypt.BCrypt.gensalt());

        com.dhanuka.backend.entities.PasswordReset reset = com.dhanuka.backend.entities.PasswordReset.builder()
                .user(user)
                .tokenHash(hashedToken)
                .expiredAt(LocalDateTime.now().plusHours(1))
                .isUsed(false)
                .build();
        
        passwordResetRepository.save(reset);

        String resetLink = frontendUrl + "/?token=" + token + "&email=" + email;
        String emailContent = "<h2>Password Reset</h2>"
                + "<p>You requested a password reset. Click the link below to set a new password:</p>"
                + "<a href=\"" + resetLink + "\">Reset Password</a>"
                + "<p>If you didn't request this, you can ignore this email.</p>";

        emailService.sendEmail(user.getEmail(), "Password Reset Request", emailContent);
    }

    @Transactional
    public void resetPassword(String token, String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        
        java.util.List<com.dhanuka.backend.entities.PasswordReset> resets = passwordResetRepository.findByUserAndIsUsedFalse(user);
        com.dhanuka.backend.entities.PasswordReset validReset = null;

        for (com.dhanuka.backend.entities.PasswordReset reset : resets) {
            if (reset.getExpiredAt().isAfter(LocalDateTime.now()) && 
                org.mindrot.jbcrypt.BCrypt.checkpw(token, reset.getTokenHash())) {
                validReset = reset;
                break;
            }
        }

        if (validReset == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset token");
        }

        if (!newPassword.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,15}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be 8-15 characters long, and include at least one uppercase letter, one lowercase letter, one number, and one special character (@#$%^&+=!)");
        }

        user.setPasswordHash(org.mindrot.jbcrypt.BCrypt.hashpw(newPassword, org.mindrot.jbcrypt.BCrypt.gensalt()));
        userRepository.save(user);

        validReset.setUsed(true);
        passwordResetRepository.save(validReset);
    }
}
