package com.nyberg.iam.events;

import org.springframework.context.ApplicationEvent;

public class PasswordResetRequestedApplicationEvent extends ApplicationEvent {

    private final UserLifecycleEvent payload;

    public PasswordResetRequestedApplicationEvent(Object source, UserLifecycleEvent payload) {
        super(source);
        this.payload = payload;
    }

    public UserLifecycleEvent getPayload() {
        return payload;
    }
}
