package com.oncontrol.auth.accounts.domain.repository;

import com.oncontrol.auth.accounts.domain.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {

    /** Email must already be normalized (see {@link Account#normalize(String)}). */
    Optional<Account> findByEmail(String email);
}
