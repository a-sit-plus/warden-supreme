package examples.javaapi;

import at.asitplus.attestation.AttestationResult;
import at.asitplus.attestation.AttestationException;
import at.asitplus.attestation.WardenDebugAttestationStatement;
import at.asitplus.attestation.android.AndroidAttestationConfiguration;
import at.asitplus.attestation.supreme.AttestationChallenge;
import at.asitplus.attestation.supreme.AttestationProof;
import at.asitplus.attestation.supreme.AttestationResponse;
import at.asitplus.attestation.IosAttestationConfiguration;
import at.asitplus.attestation.supreme.JavaAttestationVerifier;
import at.asitplus.attestation.supreme.PreAttestationError;
import at.asitplus.attestation.supreme.SupremeConfiguration;
import at.asitplus.signum.indispensable.CryptoPublicKey;
import at.asitplus.signum.indispensable.pki.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/** Complete Java usage example for the JavaAttestationVerifier adapter. */
public final class SupremeVerifierJavaApi {
    private SupremeVerifierJavaApi() {
    }

    // --8<-- [start:java-example-configuration]
    public static SupremeConfiguration newConfiguration(
            IosAttestationConfiguration ios,
            AndroidAttestationConfiguration android
    ) throws AttestationException.Configuration {
        return new SupremeConfiguration(
                /*(1)!*/ios,
                /*(2)!*/android,
                /*(3)!*/Clock.systemUTC(),
                /*(4)!*/Duration.ofMinutes(5)
        );
    }
    // --8<-- [end:java-example-configuration]

    // --8<-- [start:java-example-verifier]
    public static JavaAttestationVerifier newVerifier() throws AttestationException.Configuration {
        IosAttestationConfiguration ios = new IosAttestationConfiguration(
                new IosAttestationConfiguration.AppData(
                        /*(1)!*/"9CYHJNG644",
                        "at.asitplus.attestation-client"
                )
        );

        SupremeConfiguration configuration = /*(2)!*/newConfiguration(ios, null);
        return new JavaAttestationVerifier(configuration);
    }

    public static CompletableFuture<AttestationChallenge> issueChallenge(
            JavaAttestationVerifier verifier,
            String endpoint
    ) {
        return verifier.issueChallenge(endpoint);
    }

    public static CompletableFuture<AttestationResponse> verify(
            JavaAttestationVerifier verifier,
            AttestationProof proof
    ) {
        return verifier.verifyAttestation(proof, new JavaAttestationVerifier.Callbacks() {
            @Override
            public void onChallengeValidated(
                    /*(3)!*/AttestationChallenge challenge,
                    AttestationProof receivedProof
            ) {
                // Log or record the validated challenge here.
            }

            @Override
            public String onPreAttestationError(PreAttestationError error) {
                return null;
            }

            @Override
            public String onAttestationError(
                    AttestationResult.Error error,
                    WardenDebugAttestationStatement debugInfo
            ) {
                return null;
            }

            @Override
            public void onAttestationSuccess(
                    /*(4)!*/AttestationResult.Verified verified,
                    CryptoPublicKey publicKey
            ) {
                // Record successful attestation metrics here.
            }

            @Override
            public AttestationResponse.Failure additionalVerifications(
                    AttestationChallenge challenge,
                    AttestationProof receivedProof,
                    AttestationResult.Verified verified
            ) {
                /*(5)!*/return null;
            }

            @Override
            public List<X509Certificate> certificateIssuer(
                    AttestationResult.Verified verified,
                    AttestationProof receivedProof
            ) {
                // Replace with the certificate chain issued by the application.
                /*(6)!*/return Collections.emptyList();
            }
        });
    }

    public static void applicationFlow(AttestationProof proof) throws AttestationException.Configuration {
        /*(7)!*/JavaAttestationVerifier verifier = newVerifier();
        issueChallenge(verifier, "https://example.test/attest").thenAccept(challenge -> {
            // Send challenge to the mobile client, then receive its proof over HTTPS.
        });
        verify(verifier, proof).thenAccept(response -> {
            // Return the response to the client or handle the failure.
        });
    }
    // --8<-- [end:java-example-verifier]
}
