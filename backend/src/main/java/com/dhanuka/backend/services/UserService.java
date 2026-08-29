package com.dhanuka.backend.services;

import com.dhanuka.backend.dtos.CredentialsDto;
import com.dhanuka.backend.dtos.SignUpDto;
import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.entities.Session;
import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.repositories.PasswordResetRepository;
import com.dhanuka.backend.repositories.SessionRepository;
import com.dhanuka.backend.repositories.UserRepository;
import com.dhanuka.backend.repositories.UserTypeRepository;
import com.dhanuka.backend.entities.UserType;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final PasswordResetRepository passwordResetRepository;
    private final EmailService emailService;
    private final UserTypeRepository userTypeRepository;

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

        if ("Inactive".equalsIgnoreCase(user.getStatus())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Your account is inactive. Please contact support.");
        }

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
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .token(refreshToken)
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Normal User")
                .status(user.getStatus())
                .build();
    }

    @Transactional
    public UserDto register(SignUpDto signUpDto, String ipAddress, String userAgent) {
        String email = signUpDto.getEmail();
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        String name = signUpDto.getName();
        if (name == null || name.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name is required");
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

        UserType defaultType = userTypeRepository.findByType("Normal User").orElseGet(() -> {
            UserType newType = new UserType();
            newType.setType("Normal User");
            return userTypeRepository.save(newType);
        });

        User user = User.builder()
                .email(email)
                .name(name)
                .passwordHash(org.mindrot.jbcrypt.BCrypt.hashpw(signUpDto.getPassword(), org.mindrot.jbcrypt.BCrypt.gensalt()))
                .isEmailVerified(false)
                .userType(defaultType)
                .status("Active")
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

        String emailContent = "<h2>Registration Successful!</h2>"
                + "<p>Welcome to our platform! Your account has been successfully created.</p>"
                + "<p>You can now log in using your email address.</p>";

        emailService.sendEmail(email, "Registration Successful!", emailContent);

        return UserDto.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .name(savedUser.getName())
                .isEmailVerified(savedUser.isEmailVerified())
                .token(refreshToken)
                .userType(savedUser.getUserType().getType())
                .status(savedUser.getStatus())
                .build();
    }

    public UserDto findByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .build();
    }

    public UserDto getUserByToken(String token) {
        Session session = sessionRepository.findByRefreshToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid session"));
        if (session.isRevoked() || session.getExpiredAt().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired or revoked");
        }
        User user = session.getUser();
        if ("Inactive".equalsIgnoreCase(user.getStatus())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Your account is inactive.");
        }
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .token(token)
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Normal User")
                .status(user.getStatus())
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

    public List<UserDto> getAllUsers() {
        return userRepository.findAll().stream().map(user -> UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Unknown")
                .status(user.getStatus())
                .build()).collect(Collectors.toList());
    }

    @Transactional
    public UserDto updateUserStatus(Long userId, String status) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        
        if (user.getUserType() != null && "Super Admin".equalsIgnoreCase(user.getUserType().getType())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot change the status of a Super Admin.");
        }
        
        if (!"Active".equalsIgnoreCase(status) && !"Inactive".equalsIgnoreCase(status)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid status");
        }
        
        user.setStatus(status);
        userRepository.save(user);
        
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Unknown")
                .status(user.getStatus())
                .build();
    }
}
