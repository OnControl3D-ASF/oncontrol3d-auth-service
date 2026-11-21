package com.oncontrol.auth.audit.domain.model;

public enum AuditEventType {
    LOGIN_SUCCEEDED,
    LOGIN_FAILED,
    LOGIN_RATE_LIMITED,
    ACCOUNT_PROVISIONED,
    ACCOUNT_DEPROVISIONED
}
