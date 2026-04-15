package at.asitplus.attestation;

import at.asitplus.attestation.android.AndroidAttestationConfiguration;
import org.junit.jupiter.api.Assertions;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.List;
import java.util.Map;

public final class JavaSpringInteropAssertions {

    private JavaSpringInteropAssertions() {
    }

    public static void run() {
        Map<String, Object> springMap = Map.of(
                "applications", List.of(
                        Map.of(
                                "package-name", "at.asitplus.java-map",
                                "signer_fingerprints", List.of("NLl2LE1skNSEMZQMV73nMUJYsmQg7A")
                        )
                )
        );

        // --8<-- [start:java-spring-map]
        AndroidAttestationConfiguration fromMap = JavaSpringConfigurationLoader.load(
                springMap,
                AndroidAttestationConfiguration.class
        );
        // --8<-- [end:java-spring-map]

        Assertions.assertEquals("at.asitplus.java-map", fromMap.getApplications().get(0).getPackageName());
        Assertions.assertEquals(1, fromMap.getApplications().get(0).getSignerFingerprints().size());

        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource(
                "java-test",
                Map.of(
                        "cfg.applications[0].packageName", "at.asitplus.java-env",
                        "cfg.applications[0].signerFingerprints[0]", "NLl2LE1skNSEMZQMV73nMUJYsmQg7A"
                )
        ));

        // --8<-- [start:java-spring-env]
        AndroidAttestationConfiguration fromEnvironment = JavaSpringConfigurationLoader.load(
                environment,
                "cfg",
                AndroidAttestationConfiguration.class
        );
        // --8<-- [end:java-spring-env]

        Assertions.assertEquals("at.asitplus.java-env", fromEnvironment.getApplications().get(0).getPackageName());
        Assertions.assertEquals(1, fromEnvironment.getApplications().get(0).getSignerFingerprints().size());
    }
}
