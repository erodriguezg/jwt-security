package com.github.erodriguezg.security.jwt;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by eduardo on 24-03-17.
 */
@SuppressWarnings("squid:S2925")
public class TokenServiceTest {

    private static final Logger LOG = LoggerFactory.getLogger(TokenServiceTest.class);

    private static final String SECRET_PHRASE = "fraseSuperSecreta!!!";

    private DataSession dataSession;

    @Before
    public void before() {
        this.dataSession = new DataSession();
        dataSession.setUserId(UUID.randomUUID().toString());
        dataSession.setRoles(Arrays.asList("rol1", "rol2", "rol3"));
        LOG.info("session data map: '{}'", dataSession);
    }

    @Test
    public void testTokenCorrecto() {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(SECRET_PHRASE)
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();
        String token = tokenService.create(dataSession);
        DataSession sessionDataFromToken = tokenService.parse(token);
        assertThat(dataSession).isEqualTo(sessionDataFromToken);
    }

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testTokenIncorrecto() {

        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(SECRET_PHRASE)
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();

        String token = tokenService.create(dataSession);
        tokenService.parse(token+"a");
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

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testTokenInvalidoPorRotacion() throws InterruptedException {
        TokenService<DataSession> tokenService = new TokenServiceBuilder<>(DataSession.class)
                .setSecretWindowRotation(new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1))
                .setExpirationTime(TimeUnit.MINUTES, 1L)
                .build();
        String token = tokenService.create(dataSession);
        Thread.sleep(2000);
        tokenService.parse(token);
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
