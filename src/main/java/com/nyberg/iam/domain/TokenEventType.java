package com.nyberg.iam.domain;

public enum TokenEventType {
    LOGIN,
    REGISTER,
    REFRESH,
    CLIENT_CREDENTIALS,
    SUBJECT,
    API_KEY_CREATE,
    API_KEY_EXCHANGE,
    PASSWORD_RESET
}
