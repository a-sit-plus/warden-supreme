package examples.javaapi;

import at.asitplus.attestation.supreme.AttestationChallenge;
import at.asitplus.attestation.supreme.AttestationProof;
import at.asitplus.attestation.supreme.AttestationResponse;
import at.asitplus.attestation.supreme.JavaAttestationVerifier;
import at.asitplus.attestation.AttestationResult;
import at.asitplus.attestation.WardenDebugAttestationStatement;
import at.asitplus.attestation.supreme.PreAttestationError;
import at.asitplus.signum.indispensable.CryptoPublicKey;
import at.asitplus.signum.indispensable.pki.X509Certificate;

/** Java usage of the Java-friendly AttestationVerifier adapter. */
public final class SupremeVerifierJavaApi {
    private SupremeVerifierJavaApi() {
    }

    public static AttestationChallenge issueChallenge(
            JavaAttestationVerifier verifier,
            String endpoint
    ) {
        return verifier.issueChallenge(endpoint).join();
    }

    public static AttestationResponse verifyWithCallbacks(
            JavaAttestationVerifier verifier,
            AttestationProof proof
    ) {
        return verifier.verifyAttestation(proof, new JavaAttestationVerifier.Callbacks() {
            @Override public void onChallengeValidated(AttestationChallenge challenge, AttestationProof receivedProof) { }
            @Override public String onPreAttestationError(PreAttestationError error) { return null; }
            @Override public String onAttestationError(AttestationResult.Error error, WardenDebugAttestationStatement debugInfo) { return null; }
            @Override public void onAttestationSuccess(AttestationResult.Verified verified, CryptoPublicKey publicKey) { }
            @Override public AttestationResponse.Failure additionalVerifications(AttestationChallenge challenge, AttestationProof receivedProof, AttestationResult.Verified verified) { return null; }
            @Override public java.util.List<X509Certificate> certificateIssuer(AttestationResult.Verified verified, AttestationProof receivedProof) { return java.util.Collections.emptyList(); }
        }).join();
    }
}
