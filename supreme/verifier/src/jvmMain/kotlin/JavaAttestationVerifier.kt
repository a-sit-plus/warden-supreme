package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Java-facing adapter for [AttestationVerifier].
 *
 * The verifier itself remains suspend-based. This adapter exposes ordinary Java callback methods and
 * completes a [CompletableFuture] when the asynchronous verification operation finishes.
 */
class JavaAttestationVerifier(configuration: SupremeConfiguration) {

    private val verifier = AttestationVerifier(configuration)

    fun issueChallenge(endpoint: String): CompletableFuture<AttestationChallenge> = submit {
        verifier.issueChallenge(endpoint)
    }

    fun verifyAttestation(proof: AttestationProof, callbacks: Callbacks): CompletableFuture<AttestationResponse> =
        submit {
            verifier.verifyAttestation(
                attestationProof = proof,
                onChallengeValidated = { callbacks.onChallengeValidated(this, proof) },
                onPreAttestationError = { callbacks.onPreAttestationError(this) },
                onAttestationError = { debugInfo -> callbacks.onAttestationError(this, debugInfo) },
                onAttestationSuccess = { publicKey -> callbacks.onAttestationSuccess(this, publicKey) },
                additionalVerifications = { attestationProof, verified ->
                    callbacks.additionalVerifications(this, attestationProof, verified)
                },
                certificateIssuer = { attestationProof ->
                    callbacks.certificateIssuer(this, attestationProof)
                },
            )
        }

    interface Callbacks {
        fun onChallengeValidated(challenge: AttestationChallenge, proof: AttestationProof)

        fun onPreAttestationError(error: PreAttestationError): String?

        fun onAttestationError(
            error: AttestationResult.Error,
            debugInfo: WardenDebugAttestationStatement,
        ): String?

        fun onAttestationSuccess(verified: AttestationResult.Verified, publicKey: CryptoPublicKey)

        fun additionalVerifications(
            challenge: AttestationChallenge,
            proof: AttestationProof,
            verified: AttestationResult.Verified,
        ): AttestationResponse.Failure?

        fun certificateIssuer(
            verified: AttestationResult.Verified,
            proof: AttestationProof,
        ): List<X509Certificate>
    }

    private fun <T> submit(block: suspend () -> T): CompletableFuture<T> = CompletableFuture<T>().also { future ->
        scope.launch {
            catchingUnwrapped { block() }
                .onSuccess(future::complete)
                .onFailure(future::completeExceptionally)
        }
    }

    private companion object {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }
}
