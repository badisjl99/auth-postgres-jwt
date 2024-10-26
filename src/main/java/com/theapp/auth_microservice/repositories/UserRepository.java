package com.theapp.auth_microservice.repositories;

import com.theapp.auth_microservice.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User ,Integer> {
    Optional<User> findByEmail(String email);
}
