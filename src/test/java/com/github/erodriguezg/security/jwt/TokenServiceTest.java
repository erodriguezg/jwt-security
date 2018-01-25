package com.github.erodriguezg.security.jwt;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenServiceTest {

    private static final Logger LOG = LoggerFactory.getLogger(TokenServiceTest.class);
    private Map<String,String> sessionDataMap;

    @Before
    public void before() {
        this.sessionDataMap = new HashMap<>();
        sessionDataMap.put("userId", UUID.randomUUID().toString());
        sessionDataMap.put("roles", "rol1,rol2,rol3");
        LOG.info("session data map: '{}'", sessionDataMap);
    }

    @Test
    public void testTokenCorrecto() {
        TokenService tokenService = new TokenService("fraseSuperSecreta!!!", TimeUnit.MINUTES, 1L);
        String token = tokenService.create(sessionDataMap);
        Map<String,String> sessionDataFromToken = tokenService.parse(token);
        assertThat(sessionDataMap).isEqualTo(sessionDataFromToken);
    }

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testTokenIncorrecto() {
        TokenService tokenService = new TokenService("fraseSuperSecreta!!!", TimeUnit.MINUTES, 1L);
        String token = tokenService.create(sessionDataMap);
        Map<String,String> sessionDataFromToken = tokenService.parse(token+"a");
    }

    @Test(expected = io.jsonwebtoken.ExpiredJwtException.class)
    public void testTokenVencido() throws InterruptedException {
        SecretWindowRotation secretWindowRotation = new SecretWindowRotation("fraseSuperSecreta!!!", TimeUnit.MILLISECONDS, 20);
        TokenService tokenService = new TokenService(TimeUnit.MILLISECONDS, 10L, secretWindowRotation);
        String token = tokenService.create(sessionDataMap);
        Thread.sleep(100);
        Map<String,String> sessionDataFromToken = tokenService.parse(token);
    }

}
