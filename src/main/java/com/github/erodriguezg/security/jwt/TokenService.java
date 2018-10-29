package com.github.erodriguezg.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
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
public class TokenService<T> {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private static final SignatureAlgorithm DEFAULT_SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;

    private static final String DEFAULT_SECRET_PHRASE = "changeit_123";

    private static final long DEFAULT_EXPIRATION_TIME_MILLIS = 1000l * 60l * 20l; // 20 Minutes

    private long expirationTimeOnMillis;

    private SecretWindowRotation secretWindowRotation;

    private SignatureAlgorithm signatureAlgorithm;

    private ObjectReader objectReader;

    private ObjectWriter objectWriter;

    private final Class<T> sessionClass;

    private static SecretWindowRotation createDefaultSecretWindowRotation(String secretPhrase) {
        if (secretPhrase == null || secretPhrase.trim().isEmpty()) {
            throw new IllegalArgumentException("secret is empty");
        }
        return new SecretWindowRotation(secretPhrase, TimeUnit.MINUTES, 30);
    }

    public TokenService(Class<T> sessionClass) {
        this.sessionClass = sessionClass;
        this.expirationTimeOnMillis = DEFAULT_EXPIRATION_TIME_MILLIS;
        this.setSecretWindowRotation(DEFAULT_SECRET_PHRASE);
        this.setSignatureAlgorithm(DEFAULT_SIGNATURE_ALGORITHM);
        this.setObjectMapper(new ObjectMapper());
    }

    public void setSecretWindowRotation(SecretWindowRotation secretWindowRotation) {
        this.secretWindowRotation = secretWindowRotation;
    }

    public void setSecretWindowRotation(String secretPhrase) {
        this.secretWindowRotation = createDefaultSecretWindowRotation(secretPhrase);
    }

    public void setExpirationTime(TimeUnit timeUnit, long timeUnitDuration) {
        this.expirationTimeOnMillis = timeUnit.toMillis(timeUnitDuration);
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        if(objectMapper == null) {
            throw new IllegalStateException("ObjectMapper es nulo!");
        }
        this.objectReader = objectMapper.readerFor(this.sessionClass);
        this.objectWriter = objectMapper.writerFor(this.sessionClass);
    }

    public String create(Object payLoad) {
        String jsonPayload;
        try {
            jsonPayload = this.objectWriter.writeValueAsString(payLoad);
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
                .signWith(this.signatureAlgorithm, toMD5B64(this.secretWindowRotation.secretWithWindowRotation(0)))
                .compact();
        log.debug("token generado: '{}'", token);
        return token;
    }

    public T parse(final String tokenParam) {
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

        try {
            return objectReader.readValue(jsonPayload);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
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
