package examples.javaapi;

import at.asitplus.attestation.AttestationResult;
import at.asitplus.attestation.WardenDebugAttestationStatement;
import at.asitplus.attestation.supreme.AttestationChallenge;
import at.asitplus.attestation.supreme.AttestationProof;
import at.asitplus.attestation.supreme.AttestationResponse;
import at.asitplus.attestation.supreme.JavaAttestationVerifier;
import at.asitplus.attestation.supreme.PreAttestationError;
import at.asitplus.attestation.supreme.SupremeConfiguration;
import at.asitplus.signum.indispensable.CryptoPublicKey;
import at.asitplus.signum.indispensable.pki.X509Certificate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Java-owned test harness. Keeping the adapter and callback implementation on this side of the
 * language boundary ensures the tests compile against the API exactly as a Java consumer does.
 */
public final class JavaAttestationVerifierTestApi {
    private JavaAttestationVerifierTestApi() {
    }

    public static final class Harness {
        private final JavaAttestationVerifier verifier;

        public Harness(SupremeConfiguration configuration) {
            verifier = new JavaAttestationVerifier(configuration);
        }

        public CompletableFuture<AttestationChallenge> issueChallenge(String endpoint) {
            return verifier.issueChallenge(endpoint);
        }

        public CompletableFuture<AttestationResponse> verify(
                AttestationProof proof,
                RecordingCallbacks callbacks
        ) {
            return verifier.verifyAttestation(proof, callbacks);
        }
    }

    public static final class RecordingCallbacks implements JavaAttestationVerifier.Callbacks {
        private final List<String> calls = new ArrayList<>();
        private List<X509Certificate> certificates = Collections.emptyList();
        private AttestationResponse.Failure additionalFailure;
        private RuntimeException issuerException;
        private String preErrorExplanation;
        private String attestationErrorExplanation;
        private boolean throwOnChallengeValidated;
        private boolean throwOnAttestationSuccess;

        private AttestationChallenge validatedChallenge;
        private AttestationProof validatedProof;
        private PreAttestationError preAttestationError;
        private AttestationResult.Error attestationError;
        private WardenDebugAttestationStatement debugInfo;
        private AttestationChallenge additionalChallenge;
        private AttestationProof additionalProof;
        private AttestationResult.Verified additionalVerified;
        private AttestationResult.Verified issuerVerified;
        private AttestationProof issuerProof;
        private AttestationResult.Verified successfulVerified;
        private CryptoPublicKey successfulPublicKey;

        @Override
        public void onChallengeValidated(AttestationChallenge challenge, AttestationProof proof) {
            calls.add("challenge");
            validatedChallenge = challenge;
            validatedProof = proof;
            if (throwOnChallengeValidated) {
                throw new IllegalStateException("challenge observer exploded");
            }
        }

        @Override
        public String onPreAttestationError(PreAttestationError error) {
            calls.add("pre-error");
            preAttestationError = error;
            return preErrorExplanation;
        }

        @Override
        public String onAttestationError(
                AttestationResult.Error error,
                WardenDebugAttestationStatement debugInfo
        ) {
            calls.add("attestation-error");
            attestationError = error;
            this.debugInfo = debugInfo;
            return attestationErrorExplanation;
        }

        @Override
        public void onAttestationSuccess(
                AttestationResult.Verified verified,
                CryptoPublicKey publicKey
        ) {
            calls.add("success");
            successfulVerified = verified;
            successfulPublicKey = publicKey;
            if (throwOnAttestationSuccess) {
                throw new IllegalStateException("success observer exploded");
            }
        }

        @Override
        public AttestationResponse.Failure additionalVerifications(
                AttestationChallenge challenge,
                AttestationProof proof,
                AttestationResult.Verified verified
        ) {
            calls.add("additional");
            additionalChallenge = challenge;
            additionalProof = proof;
            additionalVerified = verified;
            return additionalFailure;
        }

        @Override
        public List<X509Certificate> certificateIssuer(
                AttestationResult.Verified verified,
                AttestationProof proof
        ) {
            calls.add("issuer");
            issuerVerified = verified;
            issuerProof = proof;
            if (issuerException != null) {
                throw issuerException;
            }
            return certificates;
        }

        public List<String> getCalls() {
            return calls;
        }

        public void setCertificates(List<X509Certificate> certificates) {
            this.certificates = certificates;
        }

        public void setAdditionalFailure(AttestationResponse.Failure additionalFailure) {
            this.additionalFailure = additionalFailure;
        }

        public void setIssuerException(RuntimeException issuerException) {
            this.issuerException = issuerException;
        }

        public void setPreErrorExplanation(String preErrorExplanation) {
            this.preErrorExplanation = preErrorExplanation;
        }

        public void setAttestationErrorExplanation(String attestationErrorExplanation) {
            this.attestationErrorExplanation = attestationErrorExplanation;
        }

        public void setThrowOnChallengeValidated(boolean throwOnChallengeValidated) {
            this.throwOnChallengeValidated = throwOnChallengeValidated;
        }

        public void setThrowOnAttestationSuccess(boolean throwOnAttestationSuccess) {
            this.throwOnAttestationSuccess = throwOnAttestationSuccess;
        }

        public AttestationChallenge getValidatedChallenge() {
            return validatedChallenge;
        }

        public AttestationProof getValidatedProof() {
            return validatedProof;
        }

        public PreAttestationError getPreAttestationError() {
            return preAttestationError;
        }

        public AttestationResult.Error getAttestationError() {
            return attestationError;
        }

        public WardenDebugAttestationStatement getDebugInfo() {
            return debugInfo;
        }

        public AttestationChallenge getAdditionalChallenge() {
            return additionalChallenge;
        }

        public AttestationProof getAdditionalProof() {
            return additionalProof;
        }

        public AttestationResult.Verified getAdditionalVerified() {
            return additionalVerified;
        }

        public AttestationResult.Verified getIssuerVerified() {
            return issuerVerified;
        }

        public AttestationProof getIssuerProof() {
            return issuerProof;
        }

        public AttestationResult.Verified getSuccessfulVerified() {
            return successfulVerified;
        }

        public CryptoPublicKey getSuccessfulPublicKey() {
            return successfulPublicKey;
        }
    }
}
