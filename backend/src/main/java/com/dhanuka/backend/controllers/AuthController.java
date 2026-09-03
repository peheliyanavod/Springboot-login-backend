package com.dhanuka.backend.controllers;

import com.dhanuka.backend.dtos.CredentialsDto;
import com.dhanuka.backend.dtos.SignUpDto;
import com.dhanuka.backend.dtos.UserDto;
import com.dhanuka.backend.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser(HttpServletRequest request) {
        String email = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName();
        UserDto userDto = userService.findByEmail(email);
        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@Valid @RequestBody CredentialsDto credentialsDto, HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        UserDto userDto = userService.login(credentialsDto, ipAddress, userAgent);

        setRefreshTokenCookie(response, userDto.getRefreshToken());
        userDto.setRefreshToken(null);

        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@Valid @RequestBody SignUpDto signUpDto, HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        UserDto createdUser = userService.register(signUpDto, ipAddress, userAgent);

        return ResponseEntity.created(URI.create("/users/" + createdUser.getId())).body(createdUser);
    }

    @PostMapping("/refresh")
    public ResponseEntity<UserDto> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = extractRefreshToken(request);
        if (refreshToken == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token missing");
        }

        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        UserDto userDto = userService.refreshAccessToken(refreshToken, ipAddress, userAgent);

        setRefreshTokenCookie(response, userDto.getRefreshToken());
        userDto.setRefreshToken(null);

        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = extractRefreshToken(request);
        if (refreshToken != null) {
            userService.logout(refreshToken);
            
            Cookie cookie = new Cookie("refresh_token", "");
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
        return ResponseEntity.ok("Logged out successfully");
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        response.addCookie(cookie);
    }

    private String extractRefreshToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("refresh_token".equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody com.dhanuka.backend.dtos.ForgotPasswordDto forgotPasswordDto) {
        userService.requestPasswordReset(forgotPasswordDto.getEmail());
        return ResponseEntity.ok("If the email exists, a password reset link has been sent.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody com.dhanuka.backend.dtos.ResetPasswordDto resetPasswordDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        userService.resetPassword(resetPasswordDto.getToken(), resetPasswordDto.getEmail(), resetPasswordDto.getNewPassword(), ipAddress);
        return ResponseEntity.ok("Password has been successfully reset.");
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@org.springframework.web.bind.annotation.RequestParam String token) {
        userService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully");
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<UserDto> verifyMfa(@org.springframework.web.bind.annotation.RequestParam String mfaToken, @org.springframework.web.bind.annotation.RequestParam int code, HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        UserDto userDto = userService.verifyMfa(mfaToken, code, ipAddress, userAgent);

        setRefreshTokenCookie(response, userDto.getRefreshToken());
        userDto.setRefreshToken(null);

        return ResponseEntity.ok(userDto);
    }
}
