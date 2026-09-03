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
import com.dhanuka.backend.repositories.EmailVerificationTokenRepository;
import com.dhanuka.backend.entities.UserType;
import com.dhanuka.backend.entities.EmailVerificationToken;
import com.warrenstrange.googleauth.GoogleAuthenticator;
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
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailService emailService;
    private final UserTypeRepository userTypeRepository;
    private final SystemLogService systemLogService;
    private final com.dhanuka.backend.config.JwtService jwtService;

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

        if (!user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Please verify your email address to log in.");
        }

        if (user.getLockTime() != null && user.getLockTime().isAfter(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is temporarily locked. Try again later.");
        }

        if (!org.mindrot.jbcrypt.BCrypt.checkpw(credentialsDto.getPassword(), user.getPasswordHash())) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);
            if (user.getFailedAttempts() >= 5) {
                user.setLockTime(LocalDateTime.now().plusMinutes(15));
            }
            userRepository.save(user);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }

        user.setFailedAttempts(0);
        user.setLockTime(null);
        userRepository.save(user);

        if (user.isMfaEnabled()) {
            String mfaToken = jwtService.generateMfaToken(user);
            return UserDto.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaToken)
                    .build();
        }

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        Session session = Session.builder()
                .user(user)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiredAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .build();
        sessionRepository.save(session);

        systemLogService.saveLog(user, ipAddress, "User logged in successfully");

        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .token(jwtToken)
                .refreshToken(refreshToken)
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

        String token = UUID.randomUUID().toString();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(savedUser)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build();
        emailVerificationTokenRepository.save(verificationToken);

        String verificationLink = frontendUrl + "/verify-email?token=" + token;
        String emailContent = "<h2>Welcome to our platform!</h2>"
                + "<p>Please verify your email address to activate your account.</p>"
                + "<p><a href=\"" + verificationLink + "\">Click here to verify your email</a></p>"
                + "<p>If you didn't request this, you can ignore this email.</p>";

        emailService.sendEmail(email, "Verify Your Email Address", emailContent);

        systemLogService.saveLog(user, ipAddress, "User registered successfully");

        return UserDto.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .name(savedUser.getName())
                .isEmailVerified(savedUser.isEmailVerified())
                .userType(savedUser.getUserType().getType())
                .status(savedUser.getStatus())
                .build();
    }

    @Transactional
    public void verifyEmail(String token) {
        EmailVerificationToken verificationToken = emailVerificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token"));

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            emailVerificationTokenRepository.delete(verificationToken);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expired. Please register again or request a new token.");
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        emailVerificationTokenRepository.delete(verificationToken);
    }

    @Transactional
    public UserDto verifyMfa(String mfaToken, int code, String ipAddress, String userAgent) {
        Boolean isMfaPending = jwtService.extractClaim(mfaToken, claims -> claims.get("mfa_pending", Boolean.class));
        if (isMfaPending == null || !isMfaPending) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid MFA token");
        }

        String email = jwtService.extractUsername(mfaToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        boolean isCodeValid = gAuth.authorize(user.getMfaSecret(), code);

        if (!isCodeValid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid MFA code");
        }

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        Session session = Session.builder()
                .user(user)
                .refreshToken(refreshToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiredAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .build();
        sessionRepository.save(session);

        systemLogService.saveLog(user, ipAddress, "User verified MFA and logged in successfully");

        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .token(jwtToken)
                .refreshToken(refreshToken)
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Normal User")
                .status(user.getStatus())
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
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Normal User")
                .status(user.getStatus())
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
        String hashedToken = org.mindrot.jbcrypt.BCrypt.hashpw(token, org.mindrot.jbcrypt.BCrypt.gensalt());

        com.dhanuka.backend.entities.PasswordReset reset = com.dhanuka.backend.entities.PasswordReset.builder()
                .user(user)
                .tokenHash(hashedToken)
                .expiredAt(LocalDateTime.now().plusHours(1))
                .isUsed(false)
                .build();
        
        com.dhanuka.backend.entities.PasswordReset savedReset = passwordResetRepository.save(reset);

        String resetLink = frontendUrl + "/?token=" + savedReset.getId() + "_" + token + "&email=" + email;
        String emailContent = "<h2>Password Reset</h2>"
                + "<p>You requested a password reset. Click the link below to set a new password:</p>"
                + "<a href=\"" + resetLink + "\">Reset Password</a>"
                + "<p>If you didn't request this, you can ignore this email.</p>";

        emailService.sendEmail(user.getEmail(), "Password Reset Request", emailContent);
    }

    @Transactional
    public void resetPassword(String token, String email, String newPassword, String ipAddress) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        
        String[] tokenParts = token.split("_");
        if (tokenParts.length != 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token format");
        }
        
        Integer resetId;
        try {
            resetId = Integer.parseInt(tokenParts[0]);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token format");
        }
        String rawToken = tokenParts[1];

        com.dhanuka.backend.entities.PasswordReset validReset = passwordResetRepository.findById(resetId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset token"));

        if (!validReset.getUser().getEmail().equals(user.getEmail()) ||
            validReset.isUsed() ||
            validReset.getExpiredAt().isBefore(LocalDateTime.now()) ||
            !org.mindrot.jbcrypt.BCrypt.checkpw(rawToken, validReset.getTokenHash())) {
            
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset token");
        }

        if (!newPassword.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,15}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be 8-15 characters long, and include at least one uppercase letter, one lowercase letter, one number, and one special character (@#$%^&+=!)");
        }

        user.setPasswordHash(org.mindrot.jbcrypt.BCrypt.hashpw(newPassword, org.mindrot.jbcrypt.BCrypt.gensalt()));
        userRepository.save(user);

        validReset.setUsed(true);
        passwordResetRepository.save(validReset);

        systemLogService.saveLog(user, ipAddress, "Password reset successful");
    }

    @Transactional
    public UserDto refreshAccessToken(String refreshToken, String ipAddress, String userAgent) {
        Session session = sessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid session"));

        if (session.isRevoked() || session.getExpiredAt().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired or revoked");
        }

        User user = session.getUser();
        if ("Inactive".equalsIgnoreCase(user.getStatus())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Your account is inactive.");
        }
        
        if (user.getLockTime() != null && user.getLockTime().isAfter(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account is temporarily locked. Try again later.");
        }

        String newJwtToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        session.setRevoked(true); // Revoke the old session
        sessionRepository.save(session);

        Session newSession = Session.builder()
                .user(user)
                .refreshToken(newRefreshToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiredAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .build();
        sessionRepository.save(newSession);

        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .isEmailVerified(user.isEmailVerified())
                .token(newJwtToken)
                .refreshToken(newRefreshToken)
                .userType(user.getUserType() != null ? user.getUserType().getType() : "Normal User")
                .status(user.getStatus())
                .build();
    }

    @Transactional
    public void logout(String token) {
        sessionRepository.findByRefreshToken(token).ifPresent(session -> {
            session.setRevoked(true);
            sessionRepository.save(session);
        });
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
    public UserDto updateUserStatus(Long userId, String status, String ipAddress) {
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

        String action = "Active".equalsIgnoreCase(status) ? "Activated" : "Deactivated";
        systemLogService.saveLog(user, ipAddress, user.getName() + "'s user account " + action);
        
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
