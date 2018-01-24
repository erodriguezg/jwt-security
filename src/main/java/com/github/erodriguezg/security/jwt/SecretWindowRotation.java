package com.github.erodriguezg.security.jwt;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class SecretWindowRotation {

    private static final Map<TimeUnit, Long> TIMEUNIT_IN_MILLIS;
    static {
        TIMEUNIT_IN_MILLIS  = new EnumMap<>(TimeUnit.class);
        TIMEUNIT_IN_MILLIS.put(TimeUnit.HOURS, 3600000L);
        TIMEUNIT_IN_MILLIS.put(TimeUnit.MINUTES, 60000L);
        TIMEUNIT_IN_MILLIS.put(TimeUnit.SECONDS, 1000L);
    }

    private final String secret;

    private final TimeZone windowTimeZone;

    private final long windowSizeInMillis;

    public SecretWindowRotation(String secret, TimeUnit windowTimeUnit, Integer windowSize) {
        this.secret = secret;
        if(TIMEUNIT_IN_MILLIS.get(windowTimeUnit) == null) {
            throw new IllegalStateException("Only Hours, Minutes And Seconds TimeUnits Supported");
        }
        this.windowSizeInMillis = TIMEUNIT_IN_MILLIS.get(windowTimeUnit) * windowSize;
        this.windowTimeZone = TimeZone.getTimeZone("UTC");
    }

    /**
     *
     * @param rotation 0 para ventana actual, -1 para ventana anterior
     * @return secret concatenado con window segun timeunit
     */
    public String secretWithWindowRotation(int rotation) {
        long actualMillis = Calendar.getInstance(windowTimeZone).getTimeInMillis();
        long millisWindow = ((actualMillis  / windowSizeInMillis) * windowSizeInMillis) - (rotation * -1 * windowSizeInMillis);
        return secret + "_" +millisWindow;
    }
}
