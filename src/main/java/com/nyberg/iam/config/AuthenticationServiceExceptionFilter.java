package com.nyberg.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Spring Security rethrows {@link AuthenticationServiceException} from the bearer-token filter,
 * which Tomcat then renders as an HTML 500. Convert those into a normal 401 API response.
 */
public class AuthenticationServiceExceptionFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint entryPoint;

    public AuthenticationServiceExceptionFilter(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (AuthenticationServiceException ex) {
            SecurityContextHolder.clearContext();
            if (!response.isCommitted()) {
                entryPoint.commence(
                        request,
                        response,
                        new InsufficientAuthenticationException(
                                ex.getMessage() != null ? ex.getMessage() : "Authentication service error",
                                ex));
            }
        }
    }
}
