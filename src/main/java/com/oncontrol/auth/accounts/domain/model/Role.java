package com.oncontrol.auth.accounts.domain.model;

/** Account roles; the values are part of the JWT contract shared with the clinical service. */
public enum Role {
    ORGANIZATION,
    DOCTOR,
    PATIENT
}
