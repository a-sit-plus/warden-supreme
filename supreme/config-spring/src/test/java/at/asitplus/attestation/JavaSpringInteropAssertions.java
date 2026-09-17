package at.asitplus.attestation;

import at.asitplus.attestation.android.AndroidAttestationConfiguration;
import at.asitplus.attestation.supreme.SupremeConfiguration;
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

        Map<String, Object> iosSpringMap = Map.of(
                "applications", List.of(
                        Map.of(
                                "teamIdentifier", "9CYHJNG644",
                                "bundleIdentifier", "at.asitplus.ios-min"
                        )
                )
        );

        IosAttestationConfiguration iosFromMap = JavaSpringConfigurationLoader.load(
                iosSpringMap,
                IosAttestationConfiguration.class
        );

        Assertions.assertEquals("9CYHJNG644", iosFromMap.getApplications().get(0).getTeamIdentifier());
        Assertions.assertEquals("at.asitplus.ios-min", iosFromMap.getApplications().get(0).getBundleIdentifier());

        StandardEnvironment iosEnvironment = new StandardEnvironment();
        iosEnvironment.getPropertySources().addFirst(new MapPropertySource(
                "java-ios-test",
                Map.of(
                        "cfg.applications[0].teamIdentifier", "9CYHJNG644",
                        "cfg.applications[0].bundleIdentifier", "at.asitplus.ios-min"
                )
        ));

        IosAttestationConfiguration iosFromEnvironment = JavaSpringConfigurationLoader.load(
                iosEnvironment,
                "cfg",
                IosAttestationConfiguration.class
        );

        Assertions.assertEquals("9CYHJNG644", iosFromEnvironment.getApplications().get(0).getTeamIdentifier());
        Assertions.assertEquals("at.asitplus.ios-min", iosFromEnvironment.getApplications().get(0).getBundleIdentifier());

        Map<String, Object> supremeSpringMap = Map.of(
                "android", springMap,
                "ios", iosSpringMap,
                "clock", "system"
        );

        SupremeConfiguration supremeFromMap = JavaSpringConfigurationLoader.load(
                supremeSpringMap,
                SupremeConfiguration.class
        );

        Assertions.assertEquals("at.asitplus.java-map", supremeFromMap.getAndroid().getApplications().get(0).getPackageName());
        Assertions.assertEquals("at.asitplus.ios-min", supremeFromMap.getIos().getApplications().get(0).getBundleIdentifier());

        StandardEnvironment supremeEnvironment = new StandardEnvironment();
        supremeEnvironment.getPropertySources().addFirst(new MapPropertySource(
                "java-supreme-test",
                Map.of(
                        "cfg.android.applications[0].packageName", "at.asitplus.java-env",
                        "cfg.android.applications[0].signerFingerprints[0]", "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
                        "cfg.ios.applications[0].teamIdentifier", "9CYHJNG644",
                        "cfg.ios.applications[0].bundleIdentifier", "at.asitplus.ios-min",
                        "cfg.clock", "system"
                )
        ));

        SupremeConfiguration supremeFromEnvironment = JavaSpringConfigurationLoader.load(
                supremeEnvironment,
                "cfg",
                SupremeConfiguration.class
        );

        Assertions.assertEquals("at.asitplus.java-env", supremeFromEnvironment.getAndroid().getApplications().get(0).getPackageName());
        Assertions.assertEquals("at.asitplus.ios-min", supremeFromEnvironment.getIos().getApplications().get(0).getBundleIdentifier());
    }
}
