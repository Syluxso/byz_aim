package com.nyberg.iam.repository;

import com.nyberg.iam.domain.MicrosoftAuthState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MicrosoftAuthStateRepository extends JpaRepository<MicrosoftAuthState, String> {
}
