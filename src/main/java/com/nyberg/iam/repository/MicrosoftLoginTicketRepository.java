package com.nyberg.iam.repository;

import com.nyberg.iam.domain.MicrosoftLoginTicket;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface MicrosoftLoginTicketRepository extends JpaRepository<MicrosoftLoginTicket, UUID> {
}
