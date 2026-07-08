package com.nyberg.iam.repository;

import com.nyberg.iam.domain.TokenEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface TokenEventRepository extends JpaRepository<TokenEvent, UUID> {
}