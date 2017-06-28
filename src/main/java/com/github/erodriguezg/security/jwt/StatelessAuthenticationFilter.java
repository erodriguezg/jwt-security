package com.github.erodriguezg.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Created by eduardo on 24-03-17.
 */
public class StatelessAuthenticationFilter extends GenericFilterBean {

    private static final Logger LOG = LoggerFactory.getLogger(StatelessAuthenticationFilter.class);

    private final TokenAuthenticationHttpHandler tokenAuthenticationHttpHandler;

    public StatelessAuthenticationFilter(TokenAuthenticationHttpHandler tokenAuthenticationHttpHandler) {
        this.tokenAuthenticationHttpHandler = tokenAuthenticationHttpHandler;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        try {
            Authentication authentication = tokenAuthenticationHttpHandler.getAuthentication(httpRequest);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (RuntimeException ex) {
            LOG.trace("No se encontro token valido", ex);
        }
        filterChain.doFilter(request, response);
        SecurityContextHolder.getContext().setAuthentication(null);
    }
}
