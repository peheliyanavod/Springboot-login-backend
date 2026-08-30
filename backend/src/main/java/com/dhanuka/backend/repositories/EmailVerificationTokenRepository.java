package com.dhanuka.backend.repositories;

import com.dhanuka.backend.entities.EmailVerificationToken;
import com.dhanuka.backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByToken(String token);
    void deleteByUser(User user);
}
