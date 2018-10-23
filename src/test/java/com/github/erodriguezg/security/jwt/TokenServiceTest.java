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
        TokenService tokenService = new TokenService(SECRET_PHRASE, TimeUnit.MINUTES, 1L);
        String token = tokenService.create(dataSession);
        DataSession sessionDataFromToken = tokenService.parse(token, DataSession.class);
        assertThat(dataSession).isEqualTo(sessionDataFromToken);
    }

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testTokenIncorrecto() {
        TokenService tokenService = new TokenService(SECRET_PHRASE, TimeUnit.MINUTES, 1L);
        String token = tokenService.create(dataSession);
        tokenService.parse(token+"a", DataSession.class);
    }

    @Test(expected = io.jsonwebtoken.ExpiredJwtException.class)
    public void testTokenVencido() throws InterruptedException {
        SecretWindowRotation secretWindowRotation = new SecretWindowRotation(SECRET_PHRASE, TimeUnit.HOURS, 1);
        TokenService tokenService = new TokenService(TimeUnit.MILLISECONDS, 10L, secretWindowRotation);
        String token = tokenService.create(dataSession);
        Thread.sleep(100);
        tokenService.parse(token, DataSession.class);
    }

    @Test
    public void testTokenValidoEnRotacionAnterior() throws InterruptedException {
        SecretWindowRotation secretWindowRotation = new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1);
        TokenService tokenService = new TokenService(TimeUnit.MINUTES, 1L, secretWindowRotation);
        String token = tokenService.create(dataSession);
        Thread.sleep(1050);
        tokenService.parse(token, DataSession.class);
    }

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testTokenInvalidoPorRotacion() throws InterruptedException {
        SecretWindowRotation secretWindowRotation = new SecretWindowRotation(SECRET_PHRASE, TimeUnit.SECONDS, 1);
        TokenService tokenService = new TokenService(TimeUnit.MINUTES, 1L, secretWindowRotation);
        String token = tokenService.create(dataSession);
        Thread.sleep(2000);
        tokenService.parse(token, DataSession.class);
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
