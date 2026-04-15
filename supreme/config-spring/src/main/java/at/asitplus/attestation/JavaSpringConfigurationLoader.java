package at.asitplus.attestation;

import org.springframework.core.env.Environment;

import java.lang.reflect.Field;
import java.util.Map;

public final class JavaSpringConfigurationLoader {

    private JavaSpringConfigurationLoader() {
    }

    public static <A extends AttestationConfiguration> A load(Environment environment, String prefix, Class<A> clazz) {
        return ConfigurationSpring.fromSpringEnvironment(readerFor(clazz), environment, prefix, clazz);
    }

    public static <A extends AttestationConfiguration> A load(Map<String, ?> configMap, Class<A> clazz) {
        return ConfigurationSpring.fromSpringMap(readerFor(clazz), configMap, clazz);
    }

    @SuppressWarnings("unchecked")
    private static <A extends AttestationConfiguration> AttestationConfiguration.Reader<A> readerFor(Class<A> clazz) {
        try {
            Field companionField = clazz.getField("Companion");
            Object companion = companionField.get(null);
            if (!(companion instanceof AttestationConfiguration.Reader<?> reader)) {
                throw new IllegalArgumentException("Companion of " + clazz.getName() + " is not an AttestationConfiguration.Reader");
            }
            return (AttestationConfiguration.Reader<A>) reader;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalArgumentException("Could not resolve AttestationConfiguration.Reader from companion of " + clazz.getName(), e);
        }
    }
}
