package com.nyberg.iam.logging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import jakarta.annotation.PostConstruct;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class LogBuffer extends AppenderBase<ILoggingEvent> {

    private static final int MAX_ENTRIES = 500;
    private final Deque<LogEntry> entries = new ConcurrentLinkedDeque<>();

    @PostConstruct
    public void attachToLogback() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        setContext(context);
        setName("LOG_BUFFER");
        start();
        context.getLogger(Logger.ROOT_LOGGER_NAME).addAppender(this);
    }

    @Override
    protected void append(ILoggingEvent event) {
        if (entries.size() >= MAX_ENTRIES) {
            entries.pollFirst();
        }
        IThrowableProxy tp = event.getThrowableProxy();
        String exception = tp != null ? tp.getClassName() + ": " + tp.getMessage() : null;
        entries.addLast(new LogEntry(
                Instant.ofEpochMilli(event.getTimeStamp()),
                event.getLevel().toString(),
                event.getLoggerName(),
                event.getFormattedMessage(),
                exception
        ));
    }

    public List<LogEntry> tail(int lines, String level) {
        List<LogEntry> all = new ArrayList<>(entries);
        List<LogEntry> filtered = (level == null || level.isBlank())
                ? all
                : all.stream().filter(e -> e.level().equalsIgnoreCase(level)).toList();
        int from = Math.max(0, filtered.size() - lines);
        return filtered.subList(from, filtered.size());
    }

    public record LogEntry(Instant ts, String level, String logger, String message, String exception) {}
}
