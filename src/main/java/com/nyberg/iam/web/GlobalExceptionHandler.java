package com.nyberg.iam.web;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ProblemDetail handle(ResponseStatusException ex) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(ex.getStatusCode(), ex.getReason());
        detail.setTitle(ex.getStatusCode().toString());
        return detail;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed");
        detail.setTitle("Bad Request");
        return detail;
    }

    @ExceptionHandler(DataAccessException.class)
    public ProblemDetail handleDataAccess(DataAccessException ex, HttpServletRequest request) {
        safeLog(request, ex);
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Database error while handling " + request.getRequestURI());
        detail.setTitle("Internal Server Error");
        return detail;
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleAll(Exception ex, HttpServletRequest request) {
        safeLog(request, ex);
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
        detail.setTitle("Internal Server Error");
        return detail;
    }

    private void safeLog(HttpServletRequest request, Exception ex) {
        try {
            log.error("Unhandled {} on {} {}: {}",
                    ex.getClass().getSimpleName(),
                    request.getMethod(),
                    request.getRequestURI(),
                    ex.getMessage());
            log.debug("Full stack trace for {} {}", request.getMethod(), request.getRequestURI(), ex);
        } catch (Throwable ignored) {
            // Never let logging failures turn API errors into Tomcat HTML 500 pages.
        }
    }
}
