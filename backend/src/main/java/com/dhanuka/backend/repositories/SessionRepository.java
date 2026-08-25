package com.dhanuka.backend.repositories;

import com.dhanuka.backend.entities.Session;
import com.dhanuka.backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByRefreshToken(String refreshToken);
    List<Session> findByUser(User user);
}
