package com.github.erodriguezg.security.jwt;

import io.jsonwebtoken.SignatureAlgorithm;

import java.util.concurrent.TimeUnit;

public class TokenServiceBuilder<T> {

    private TokenService<T> tokenService;

    public TokenServiceBuilder(Class<T> clazz) {
        this.tokenService = new TokenService<>(clazz);
    }

    public TokenServiceBuilder<T> setSecretWindowRotation(SecretWindowRotation secretWindowRotation) {
        this.tokenService.setSecretWindowRotation(secretWindowRotation);
        return this;
    }

    public TokenServiceBuilder<T> setSecretWindowRotation(String secretPhrase) {
        this.tokenService.setSecretWindowRotation(secretPhrase);
        return this;
    }

    public TokenServiceBuilder<T> setExpirationTime(TimeUnit timeUnit, long timeUnitDuration) {
        this.tokenService.setExpirationTime(timeUnit, timeUnitDuration);
        return this;
    }

    public TokenServiceBuilder<T> setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.tokenService.setSignatureAlgorithm(signatureAlgorithm);
        return this;
    }




    public TokenService<T> build() {
        return tokenService;
    }
}
