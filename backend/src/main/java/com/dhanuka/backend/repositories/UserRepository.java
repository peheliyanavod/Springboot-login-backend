package com.dhanuka.backend.repositories;

import com.dhanuka.backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    void updateStatus(@org.springframework.data.repository.query.Param("id") Long id, @org.springframework.data.repository.query.Param("status") String status);
}
