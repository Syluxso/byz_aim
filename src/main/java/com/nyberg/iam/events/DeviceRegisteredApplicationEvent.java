package com.nyberg.iam.events;

import org.springframework.context.ApplicationEvent;

public class DeviceRegisteredApplicationEvent extends ApplicationEvent {

    private final UserLifecycleEvent payload;

    public DeviceRegisteredApplicationEvent(Object source, UserLifecycleEvent payload) {
        super(source);
        this.payload = payload;
    }

    public UserLifecycleEvent getPayload() {
        return payload;
    }
}
