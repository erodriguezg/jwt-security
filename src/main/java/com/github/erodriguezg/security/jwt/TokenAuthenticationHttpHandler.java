package com.github.erodriguezg.security.jwt;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Function;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenAuthenticationHttpHandler<T> {

    private static final String JWT_HEADER_STANDART = "Authorization";

    private final String authHeaderName;

    private final TokenService tokenService;

    private final Function<T, Authentication> sessionToAuthFunction;

    private final Function<Authentication, T> authToSessionFunction;

    private final Class<T> sessionClass;


    public TokenAuthenticationHttpHandler(Class<T> sessionClass,
                                          TokenService tokenService,
                                          Function<T, Authentication> sessionToAuthFunction,
                                          Function<Authentication, T> authToSessionFunction) {
        this(sessionClass, JWT_HEADER_STANDART, tokenService, sessionToAuthFunction, authToSessionFunction);
    }

    public TokenAuthenticationHttpHandler(Class<T> sessionClass, String authHeaderName,
                                          TokenService tokenService,
                                          Function<T, Authentication> sessionToAuthFunction,
                                          Function<Authentication, T> authToSessionFunction) {
        this.authHeaderName = authHeaderName;
        this.tokenService = tokenService;
        this.sessionToAuthFunction = sessionToAuthFunction;
        this.authToSessionFunction = authToSessionFunction;
        this.sessionClass = sessionClass;
    }

    public void addAuthentication(HttpServletResponse response, Authentication authentication) {
        String token = tokenService.create(this.authToSessionFunction.apply(authentication));
        if (JWT_HEADER_STANDART.equals(authHeaderName)) {
            token = "Bearer " + token;
        }
        response.addHeader(authHeaderName, token);
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(authHeaderName);
        if (token == null) {
            return null;
        }
        token = token.replace("Bearer ", "").trim();
        if (token.isEmpty()) {
            return null;
        }
        final T sessionData = tokenService.parse(token,this.sessionClass);
        if (sessionData != null) {
            return this.sessionToAuthFunction.apply(sessionData);
        }
        return null;
    }
}