package com.nyberg.iam.logging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LogController {

    private final LogBuffer logBuffer;

    @GetMapping("/api/v1/admin/logs")
    public List<LogBuffer.LogEntry> getLogs(
            @RequestParam(defaultValue = "200") int lines,
            @RequestParam(required = false) String level) {
        try {
            return logBuffer.tail(Math.min(Math.max(lines, 1), 500), level);
        } catch (Exception ex) {
            log.warn("Failed to read log buffer: {}", ex.toString());
            return List.of();
        }
    }
}
