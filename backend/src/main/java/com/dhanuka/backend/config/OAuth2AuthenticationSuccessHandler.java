package com.dhanuka.backend.config;

import com.dhanuka.backend.entities.Session;
import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.repositories.SessionRepository;
import com.dhanuka.backend.repositories.UserRepository;
import com.dhanuka.backend.services.SystemLogService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final SystemLogService systemLogService;

    @Value("${app.frontend.url:http://localhost:4200}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null) {
            String jwtToken;
            if (user.isMfaEnabled()) {
                jwtToken = jwtService.generateMfaToken(user);
                response.sendRedirect(frontendUrl + "/oauth2/redirect?mfaToken=" + jwtToken);
                return;
            } else {
                jwtToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                Session session = Session.builder()
                        .user(user)
                        .refreshToken(refreshToken)
                        .ipAddress(request.getRemoteAddr())
                        .userAgent(request.getHeader("User-Agent"))
                        .expiredAt(LocalDateTime.now().plusDays(7))
                        .isRevoked(false)
                        .build();
                sessionRepository.save(session);

                systemLogService.saveLog(user, request.getRemoteAddr(), "User logged in via OAuth2");

                Cookie cookie = new Cookie("refresh_token", refreshToken);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(7 * 24 * 60 * 60);
                response.addCookie(cookie);

                response.sendRedirect(frontendUrl + "/oauth2/redirect?token=" + jwtToken);
            }
        } else {
            response.sendRedirect(frontendUrl + "/login?error=true");
        }
    }
}
