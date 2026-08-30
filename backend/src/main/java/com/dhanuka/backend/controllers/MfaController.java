package com.dhanuka.backend.controllers;

import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.repositories.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final UserRepository userRepository;

    @GetMapping("/setup")
    public ResponseEntity<Map<String, String>> setupMfa(Principal principal) {
        if (principal == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = gAuth.createCredentials();

        user.setMfaSecret(key.getKey());
        userRepository.save(user);

        String otpAuthUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("MyApp", user.getEmail(), key);

        Map<String, String> response = new HashMap<>();
        response.put("secret", key.getKey());
        response.put("qrCodeUrl", otpAuthUrl);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-setup")
    public ResponseEntity<String> verifySetup(@RequestParam int code, Principal principal) {
        if (principal == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        boolean isCodeValid = gAuth.authorize(user.getMfaSecret(), code);

        if (isCodeValid) {
            user.setMfaEnabled(true);
            userRepository.save(user);
            return ResponseEntity.ok("MFA successfully enabled.");
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid MFA code.");
        }
    }
}
