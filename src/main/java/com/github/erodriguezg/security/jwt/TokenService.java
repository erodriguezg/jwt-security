package com.github.erodriguezg.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Created by eduardo on 24-03-17.
 */
public class TokenService {

    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);

    private String secretB64;

    private long expirationTimeOnMillis;

    private TimeUnit rotationWindow;

    public TokenService(String secretPhrase, TimeUnit timeUnit, long timeUnitDuration) {
        if (secretPhrase == null || secretPhrase.trim().isEmpty()) {
            throw new IllegalArgumentException("secret is empty");
        }
        this.secretB64 = Base64.getEncoder().encodeToString(secretPhrase.getBytes());
        this.expirationTimeOnMillis = timeUnit.toMillis(timeUnitDuration);
    }

    public Map<String, String> parse(String token) {
        token = token.replace("Bearer ", "");
        LOG.debug("token entrada: '{}'", token);
        String jsonPayload = Jwts.parser()
                .setSigningKey(secretB64)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
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
                .signWith(SignatureAlgorithm.HS512, secretB64)
                .compact();
        LOG.debug("token generado: '{}'", token);
        return token;
    }


    private String toMD5(String secret) {
        return null;
    }

    /**
     * rota el password segun la ventaja de tiempo
     * @param secret
     * @param deltaRotation 0 significa ventana actual, -1 ventana anterior
     * @return secret concatenado con milli de la ventana
     */
    private String rotationWindow(String secret, int deltaRotation) {
        return null;
    }

}
