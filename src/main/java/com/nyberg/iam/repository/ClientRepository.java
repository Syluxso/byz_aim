package com.nyberg.iam.repository;

import com.nyberg.iam.domain.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ClientRepository extends JpaRepository<Client, UUID> {
    Optional<Client> findByClientIdAndActiveTrue(String clientId);
}