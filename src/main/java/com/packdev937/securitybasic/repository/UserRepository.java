package com.packdev937.securitybasic.repository;

import com.packdev937.securitybasic.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    void save(Optional<User> userEntity);
}
