package com.github.erodriguezg.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private long expirationTimeOnMillis;

    private SecretWindowRotation secretWindowRotation;

    private static SecretWindowRotation createDefaultSecretWindowRotation(String secretPhrase) {
        if (secretPhrase == null || secretPhrase.trim().isEmpty()) {
            throw new IllegalArgumentException("secret is empty");
        }
        return new SecretWindowRotation(secretPhrase, TimeUnit.MINUTES, 30);
    }

    public TokenService(String secretPhrase, TimeUnit timeUnit, long timeUnitDuration) {
        this(timeUnit, timeUnitDuration, createDefaultSecretWindowRotation(secretPhrase));
    }

    public TokenService(TimeUnit timeUnit, long timeUnitDuration, SecretWindowRotation secretWindowRotation) {
        this.secretWindowRotation = secretWindowRotation;
        this.expirationTimeOnMillis = timeUnit.toMillis(timeUnitDuration);
    }

    public <T> T parse(final String tokenParam, Class<T> clazz ) {
        String token = tokenParam.replace("Bearer ", "");
        log.debug("token entrada: '{}'", token);
        String jsonPayload = null;
        RuntimeException exJwtParser = null;
        for (int window = 0; window < 2; window++) {
            log.debug("window: {}", window);
            try {
                jsonPayload = Jwts.parser()
                        .setSigningKey(toMD5B64(this.secretWindowRotation.secretWithWindowRotation(window * -1)))
                        .parseClaimsJws(token)
                        .getBody()
                        .getSubject();
                if (jsonPayload != null) {
                    break;
                }
            } catch (ExpiredJwtException ex) {
                throw ex;
            } catch (RuntimeException ex) {
                exJwtParser = ex;
            }
        }

        if (jsonPayload == null && exJwtParser != null) {
            throw exJwtParser;
        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(jsonPayload, clazz);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public String create(Object payLoad) {
        ObjectMapper mapper = new ObjectMapper();
        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(payLoad);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationTimeOnMillis);
        String token = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(jsonPayload)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS512, toMD5B64(this.secretWindowRotation.secretWithWindowRotation(0)))
                .compact();
        log.debug("token generado: '{}'", token);
        return token;
    }

    private String toMD5B64(String secret) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return Base64.getEncoder().encodeToString(md.digest(secret.getBytes()));
    }

}
