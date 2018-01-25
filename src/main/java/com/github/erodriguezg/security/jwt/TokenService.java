package com.github.erodriguezg.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenService {

    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);

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

    public Map<String, String> parse(final String tokenParam) {
        String token = tokenParam.replace("Bearer ", "");
        LOG.debug("token entrada: '{}'", token);
        String jsonPayload = null;
        RuntimeException exJwtParser = null;
        for(int window = 0; window < 2; window++) {
            try {
                jsonPayload = Jwts.parser()
                        .setSigningKey(toMD5B64(this.secretWindowRotation.secretWithWindowRotation(window*-1)))
                        .parseClaimsJws(token)
                        .getBody()
                        .getSubject();
                if(jsonPayload != null) {
                    break;
                }
            }catch (RuntimeException ex) {
                exJwtParser = ex;
            }
        }

        if(jsonPayload == null && exJwtParser != null) {
            throw exJwtParser;
        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            TypeReference<HashMap<String, Object>> typeRef = new TypeReference<HashMap<String, Object>>() {
            };
            return mapper.readValue(jsonPayload, typeRef);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public String create(Map<String, String> subjectMap) {
        ObjectMapper mapper = new ObjectMapper();
        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(subjectMap);
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
        LOG.debug("token generado: '{}'", token);
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
