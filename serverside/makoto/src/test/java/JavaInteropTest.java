import at.asitplus.attestation.AttestationService;
import at.asitplus.attestation.Warden;
import at.asitplus.attestation.IosAttestationConfiguration;
import at.asitplus.attestation.KeyAttestation;
import at.asitplus.attestation.android.AndroidAttestationChecker;
import at.asitplus.attestation.android.AndroidAttestationConfiguration;
import at.asitplus.attestation.android.HardwareAttestationChecker;
import at.asitplus.attestation.android.PatchLevel;
import at.asitplus.attestation.android.exceptions.AndroidAttestationException;
import at.asitplus.attestation.android.exceptions.AttestationValueException;
import at.asitplus.attestation.android.exceptions.CertificateInvalidException;
import at.asitplus.attestation.android.exceptions.RevocationException;
import com.google.android.attestation.ParsedAttestationRecord;
import org.junit.jupiter.api.Assertions;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.*;


public class JavaInteropTest {


    public static void testDefaults() {
        Assertions.assertThrows(AndroidAttestationException.class, () -> {
                    new Warden(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData(
                                    "at.asitplus.attestation-example", Collections.emptyList())).build(),
                            new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")));
                },
                "No signature digests specified");

        Assertions.assertThrows(AndroidAttestationException.class, () -> {
                    new Warden(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>()
                            )).build(),
                            new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AndroidAttestationException.class, () -> {
                    new Warden(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>(),
                                    10)
                            ).build(),
                            new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example")),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AndroidAttestationException.class, () -> {
                    new Warden(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>(),
                                    10,
                                    10000)
                            ).build(),
                            new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example",
                                    true)),
                            Duration.ZERO);
                },
                "No signature digests specified");

        Assertions.assertThrows(AndroidAttestationException.class, () -> {
                    new Warden(
                            new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                                    new ArrayList<>()
                            )).build(),
                            new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                                    "1234567890",
                                    "at.asitplus.attestation-example",
                                    false),
                                    new IosAttestationConfiguration.OsVersions("14.1", "18A8395")),
                            Duration.ZERO);
                },
                "No signature digests specified");
    }

    public static void testAttestationCallsJavaFriendliness() throws NoSuchAlgorithmException {
        AttestationService service = new Warden(
                new AndroidAttestationConfiguration.Builder(new AndroidAttestationConfiguration.AppData("at.asitplus.attestation-example",
                        Arrays.asList(new byte[][]{new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8}}))
                ).build(),
                new IosAttestationConfiguration(new IosAttestationConfiguration.AppData(
                        "1234567890",
                        "at.asitplus.attestation-example",
                        false),
                        new IosAttestationConfiguration.OsVersions("14.1", "18A8395")),
                Duration.ZERO);

        KeyAttestation<ECPublicKey> keyAttestationResult = service.verifyKeyAttestation(Collections.emptyList(),
                new byte[]{0, 2, 3, 2, 2}, (ECPublicKey) KeyPairGenerator.getInstance("EC").
                        generateKeyPair().getPublic());


        Assertions.assertFalse(keyAttestationResult.isSuccess());
        Assertions.assertNull(keyAttestationResult.getAttestedPublicKey());
    }

    public static void javaDemo() {
        byte[] challenge = new byte[]{0, 2, 3, 4, 5, 6};
        List<X509Certificate> certificateChain = Collections.emptyList();

        List<AndroidAttestationConfiguration.AppData> apps = new LinkedList<>();

        apps.add(new AndroidAttestationConfiguration.AppData(
                "at.asitplus.example",
                Collections.singletonList(Base64.getDecoder().decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU="))
        ));
        apps.add(new AndroidAttestationConfiguration.AppData(
                "at.asitplus.anotherexample",
                Collections.singletonList(Base64.getDecoder().decode("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=")),
                2
        ));
        AndroidAttestationConfiguration config = new AndroidAttestationConfiguration.Builder(apps)
                .androidVersion(11000)
                .ingoreLeafValidity()
                .patchLevel(new PatchLevel(2023, 03))
                .verificationSecondsOffset(-500) //we to account for time drift
                .build();

        AndroidAttestationChecker checker = new HardwareAttestationChecker(config);
        try {
            ParsedAttestationRecord attestationRecord = checker.verifyAttestation(certificateChain, new Date(), challenge);
            //all good
        } catch (AttestationValueException | CertificateInvalidException | RevocationException e) {
            //untrusted device/app
        }
    }

}
