package com.github.erodriguezg.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by eduardo on 24-03-17.
 */
@SuppressWarnings("squid:S2925")
public class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private static final String SECRET_PHRASE = "fraseSuperSecreta!!!";

    private DataSession dataSession;

    @Before
    public void before() {
        this.dataSession = new DataSession();
        dataSession.setUserId(UUID.randomUUID().toString());
        dataSession.setRoles(Arrays.asList("rol1", "rol2", "rol3"));
        log.info("session data map: '{}'", dataSession);
    }

    @Test
    public void testTokenCorrecto() {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(SECRET_PHRASE)
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();
        String token = tokenService.create(dataSession);
        log.info("token: {}", token);
        DataSession sessionDataFromToken = tokenService.parse(token);
        assertThat(dataSession).isEqualTo(sessionDataFromToken);
    }

    @Test(expected = io.jsonwebtoken.security.SecurityException.class)
    public void testTokenIncorrecto() {

        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(SECRET_PHRASE)
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();

        String token = tokenService.create(dataSession);
        tokenService.parse(token + "a");
    }

    @Test(expected = io.jsonwebtoken.ExpiredJwtException.class)
    public void testTokenVencido() throws InterruptedException {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(new SecretWindowRotation(SECRET_PHRASE, TimeUnit.HOURS, 1))
                .setExpirationTime(TimeUnit.MILLISECONDS, 10L)
                .build();
        String token = tokenService.create(dataSession);
        Thread.sleep(100);
        tokenService.parse(token);
    }

    @Test
    public void testTokenValidoEnRotacionAnterior() throws InterruptedException {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1))
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();
        String token = tokenService.create(dataSession);
        Thread.sleep(1050);
        tokenService.parse(token);
    }

    @Test(expected = io.jsonwebtoken.security.SecurityException.class)
    public void testTokenInvalidoPorRotacion() throws InterruptedException {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1))
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();
        String token = tokenService.create(dataSession);
        Thread.sleep(2000);
        tokenService.parse(token);
    }

    @Test
    public void testTokenSecondsToExp() {
        long expTimeMinutes = 30L;
        long secondsToExpExpected = expTimeMinutes * 60;
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1))
                .setExpirationTime(TimeUnit.MINUTES, expTimeMinutes)
                .build();
        String token = tokenService.create(dataSession);
        long secondsToExpActual = getSecondsToExp(token);
        log.info("expTimeMinutes: {}", expTimeMinutes);
        log.info("secondsToExpExpected: {}", secondsToExpExpected);
        log.info("secondsToExpActual: {}", secondsToExpActual);
        assertThat(secondsToExpActual).isEqualTo(secondsToExpExpected);
    }

    private long getSecondsToExp(String token) {
        String payloadB64 = token.split("\\.")[1];
        String payloadText = new String(Base64.getUrlDecoder().decode(payloadB64));
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.reader().readTree(payloadText).get("secondsToExp").asLong();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static class DataSession {
        private String userId;
        private List<String> roles;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DataSession that = (DataSession) o;
            return Objects.equals(userId, that.userId) &&
                    Objects.equals(roles, that.roles);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, roles);
        }

        @Override
        public String toString() {
            return "DataSession{" +
                    "userId='" + userId + '\'' +
                    ", roles=" + roles +
                    '}';
        }
    }

}
