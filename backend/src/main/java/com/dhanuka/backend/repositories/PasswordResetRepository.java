package com.dhanuka.backend.repositories;

import com.dhanuka.backend.entities.PasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetRepository extends JpaRepository<PasswordReset, Integer> {
    Optional<PasswordReset> findByTokenHash(String tokenHash);
}
