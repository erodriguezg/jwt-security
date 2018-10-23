package com.github.erodriguezg.security.jwt;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Function;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenAuthenticationHttpHandler {

    private static final String JWT_HEADER_STANDART = "Authorization";

    private final String authHeaderName;

    private final TokenService tokenService;

    private final Function<Object, Authentication> sessionToAuthFunction;

    private final Function<Authentication, Object> authToSessionFunction;


    public TokenAuthenticationHttpHandler(TokenService tokenService,
                                          Function<Object, Authentication> sessionToAuthFunction,
                                          Function<Authentication, Object> authToSessionFunction) {
        this(JWT_HEADER_STANDART, tokenService, sessionToAuthFunction, authToSessionFunction);
    }

    public TokenAuthenticationHttpHandler(String authHeaderName,
                                          TokenService tokenService,
                                          Function<Object, Authentication> sessionToAuthFunction,
                                          Function<Authentication, Object> authToSessionFunction) {
        this.authHeaderName = authHeaderName;
        this.tokenService = tokenService;
        this.sessionToAuthFunction = sessionToAuthFunction;
        this.authToSessionFunction = authToSessionFunction;
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
        final Object sessionData = tokenService.parse(token, Object.class);
        if (sessionData != null) {
            return this.sessionToAuthFunction.apply(sessionData);
        }
        return null;
    }
}