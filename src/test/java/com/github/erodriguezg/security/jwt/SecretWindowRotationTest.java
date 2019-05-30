package com.github.erodriguezg.security.jwt;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

public class SecretWindowRotationTest {

    private static final Logger log = LoggerFactory.getLogger(SecretWindowRotationTest.class);

    @Test
    public void test() throws InterruptedException {
        SecretWindowRotation secretWindowRotation = new SecretWindowRotation("secreto", TimeUnit.HOURS, 1);

        String secret0 = secretWindowRotation.secretWithWindowRotation(-1);
        String secret1 = secretWindowRotation.secretWithWindowRotation(0);
        Thread.sleep(1000);
        String secret2 = secretWindowRotation.secretWithWindowRotation(0);
        Thread.sleep(1000);
        String secret3 = secretWindowRotation.secretWithWindowRotation(-1);
        String secret4 = secretWindowRotation.secretWithWindowRotation(0);
        Thread.sleep(2000);
        String secret5 = secretWindowRotation.secretWithWindowRotation(-2);
        String secret6 = secretWindowRotation.secretWithWindowRotation(-1);
        String secret7 = secretWindowRotation.secretWithWindowRotation(0);

        log.info("secret0 {}", secret0);
        log.info("secret1 {}", secret1);
        log.info("secret2 {}", secret2);
        log.info("secret3 {}", secret3);
        log.info("secret4 {}", secret4);
        log.info("secret5 {}", secret5);
        log.info("secret6 {}", secret6);
        log.info("secret7 {}", secret7);
        assertThat(secret0).isEqualTo(secret3).isEqualTo(secret6);
        assertThat(secret1).isEqualTo(secret1).isEqualTo(secret2).isEqualTo(secret4).isEqualTo(secret7);
        assertThat(secret5).isNotEqualTo(secret0);
        assertThat(secret5).isNotEqualTo(secret1);
    }

}
