package com.dhanuka.backend.services;

import com.dhanuka.backend.entities.User;
import com.dhanuka.backend.entities.UserType;
import com.dhanuka.backend.repositories.UserRepository;
import com.dhanuka.backend.repositories.UserTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserTypeRepository userTypeRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        
        String providerId = oAuth2User.getAttribute("sub");
        if (providerId == null) {
            Object idObj = oAuth2User.getAttribute("id");
            if (idObj != null) {
                providerId = String.valueOf(idObj);
            }
        }
        
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            if (user.getAuthProvider() == null) {
                user.setAuthProvider(registrationId);
                user.setProviderId(providerId);
                user.setEmailVerified(true);
                userRepository.save(user);
            }
        } else {
            UserType defaultType = userTypeRepository.findByType("Normal User").orElseGet(() -> {
                UserType newType = new UserType();
                newType.setType("Normal User");
                return userTypeRepository.save(newType);
            });

            user = User.builder()
                    .email(email)
                    .name(name != null ? name : email)
                    .isEmailVerified(true)
                    .authProvider(registrationId)
                    .providerId(providerId)
                    .userType(defaultType)
                    .status("Active")
                    .build();
            userRepository.save(user);
        }

        return oAuth2User;
    }
}
