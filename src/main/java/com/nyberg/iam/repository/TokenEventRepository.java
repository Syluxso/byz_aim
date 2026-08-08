package com.nyberg.iam.repository;

import com.nyberg.iam.domain.TokenEvent;
import com.nyberg.iam.domain.TokenEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface TokenEventRepository extends JpaRepository<TokenEvent, UUID> {

    List<TokenEvent> findByUserIdAndEventTypeInOrderByCreatedAtDesc(
            UUID userId,
            Collection<TokenEventType> eventTypes
    );
}