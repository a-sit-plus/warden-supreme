package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.attestation.supreme.PreAttestationError.ChallengeVerification
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import kotlinx.datetime.TimeZone
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime

/**
 * Verifies attestation statements and issues certificates on success.
 * Expects a preconfigured [Warden] instance and an OID to be used in a CSR to convey an attestation statement.
 * Also requires a [challengeValidator], checking challenges validity and invalidating it once used.
 */
class AttestationValidator(
    private val warden: Warden,
    val attestationProofOID: ObjectIdentifier,
    private val challengeValidator: ChallengeValidator
) {
    /**
     *
     * @param androidAttestationConfiguration Configuration for Android key attestation.
     * See [AndroidAttestationConfiguration]
     * for details.
     * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param clock a clock to set the time of verification (used for certificate validity checks)
     * @param verificationTimeOffset allows for fine-grained clock drift compensation (this duration is added to the certificate
     * @param challengeValidator lambda checking challenges validity and invalidating it once used
     * validity checks); can be negative.
     */
    @OptIn(ExperimentalTime::class)
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        iosAttestationConfiguration: IosAttestationConfiguration,

        attestationProofOID: ObjectIdentifier,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = Duration.ZERO,
        challengeValidator: ChallengeValidator
    ) : this(
        Makoto(androidAttestationConfiguration, iosAttestationConfiguration, clock, verificationTimeOffset),
        attestationProofOID,
        challengeValidator
    )

    /**
     * alias for [warden]
     */
    val makoto: Makoto get() = warden

    /**
     * Issues a new attestation challenge, using [nonce], valid for a duration of [validity], expecting an CSR containing an attestation statement to be `HTTP POST`ed to [postEndpoint].
     * It is recommended, to pass  a [timeZone].
     */
    fun issueChallenge(
        nonce: ByteArray,
        validity: Duration?,
        timeZone: TimeZone?,
        postEndpoint: String,
        timeOffset: Duration
    ) =
        AttestationChallenge(
            issuedAt = Clock.System.now() + timeOffset,
            validity,
            timeZone,
            nonce,
            postEndpoint,
            attestationProofOID
        )

    /**
     * verifies the received CSR:
     * * Validates nonce contained in the [csr] against the [challengeValidator]
     * * extracts the attestation statement from the [csr]
     * * calls upon [warden] for key attestation based on the extracted attestation statement
     * * verifies the [csr] signature against the contained public key
     *
     * Iff all verifications succeed, [certificateIssuer] is invoked and the resulting certificate chain
     * is returned as an [AttestationResponse.Success].
     *
     * [onPreAttestationError] allows side-effect-free investigating/logging/handling high-level errors and preparing error details for the client
     * This comprises
     * * errors in signing a binding certificate,
     * * issues trying to extract the challenge from the CSR
     * * challenge validation errors
     *
     * [onAttestationError] allows side-effect-free investigating attestation statement verification errors.
     * Gives you not only the Attestation error, but also a ready-made [WardenDebugAttestationStatement].
     * Those are essentially attestation statements received from the client that do not
     * comply with the configured attestation policy (package identifier, bootloader lock state, …).
     * In case the CSR signature is invalid, this callback is also invoked.
     *
     * [onAttestationSuccess] allows side-effect-free operations on successful attestation statement verification.
     * Logging and/or collecting numbers for statistical analysis come to mind.
     *
     * Should any verification step fail, an [AttestationResponse.Failure] is returned.
     */
    @OptIn(ExperimentalStdlibApi::class)
    suspend fun verifyKeyAttestation(
        csr: Pkcs10CertificationRequest,
        onPreAttestationError: PreAttestationError.() -> String? = { null },
        onAttestationError: AttestationResult.Error.(debugInfo: WardenDebugAttestationStatement) -> String? = { null },
        onAttestationSuccess: AttestationResult.Verified.(CryptoPublicKey) -> Unit = { },
        certificateIssuer: CertificateIssuer,
    ): AttestationResponse {
        val nonce = csr.tbsCsr.challenge.getOrElse {
            val explanation =
                catchingUnwrapped { PreAttestationError.ChallengeExtraction(it).onPreAttestationError() }.getOrNull()
            return Failure(Failure.Type.CONTENT, explanation)
        }

        when (val challengeValidationResult = challengeValidator.invoke(nonce)) {
            is ChallengeValidationResult.Failure -> {
                val explanation = catchingUnwrapped {
                    ChallengeVerification(
                        challengeValidationResult.reason,
                        nonce
                    ).onPreAttestationError()
                }.getOrNull()
                return Failure(
                    Failure.Type.CONTENT,
                    explanation
                )
            }

            ChallengeValidationResult.Success -> {}
        }

        val attestationStatement = csr.tbsCsr.attestationStatementForOid(attestationProofOID)
            .getOrElse {
                val explanation = catchingUnwrapped {
                    PreAttestationError.AttestationStatementExtraction(it, csr).onPreAttestationError()
                }.getOrNull()
                return Failure(
                    Failure.Type.CONTENT,
                    explanation
                )
            }

        val result = warden.verifyKeyAttestation(attestationStatement, nonce)
        return result.fold(
            onError = {
                val explanation = catchingUnwrapped { it.onAttestationError(warden.collectDebugInfo(attestationStatement,nonce)) }.getOrNull()
                when (it.cause) {
                    null, is AttestationException.Content -> Failure(Failure.Type.CONTENT, explanation)
                    is AttestationException.Certificate.Time -> Failure(Failure.Type.TIME, explanation)
                    is AttestationException.Certificate.Trust -> Failure(Failure.Type.TRUST, explanation)
                    is AttestationException.Configuration -> Failure(Failure.Type.INTERNAL, explanation)
                }
            },
            onSuccess = { pubKey, details ->
                details as AttestationResult.Verified
                val signature =
                    (csr.signatureAlgorithm as SpecializedSignatureAlgorithm).getJCASignatureInstance().getOrElse {
                        //TODO: is this internal?
                        val explanation = catchingUnwrapped {
                            PreAttestationError.OperationalError(it).onPreAttestationError()
                        }.getOrNull()
                        return Failure(
                            Failure.Type.INTERNAL,
                            explanation
                        )
                    }

                catching {
                    signature.initVerify(pubKey)
                    if (signature.verify(csr.decodedSignature.getOrThrow().jcaSignatureBytes)) {
                        val explanation = catchingUnwrapped {
                            AttestationResult.Error("CSR signature verification failed").onAttestationError(warden.collectDebugInfo(attestationStatement,nonce))
                        }.getOrNull()
                        return Failure(
                            Failure.Type.TRUST,
                            explanation
                        )
                    }
                }.onFailure {
                    val explanation = catchingUnwrapped {
                        PreAttestationError.OperationalError(it).onPreAttestationError()
                    }.getOrNull()
                    return Failure(
                        Failure.Type.INTERNAL,
                        explanation
                    )
                }

                certificateIssuer.invoke(csr).fold(
                    onSuccess = {
                        catchingUnwrapped {
                            details.onAttestationSuccess(
                                pubKey.toCryptoPublicKey().getOrThrow()/*TODO*/
                            )
                        }
                        AttestationResponse.Success(it)
                    },
                    onFailure = {
                        val explanation = catchingUnwrapped {
                            PreAttestationError.OperationalError(it).onPreAttestationError()
                        }.getOrNull()
                        Failure(
                            Failure.Type.INTERNAL,
                            explanation
                        )
                    }
                )
            }
        )
    }
}

/**
 * invoked from [AttestationValidator.verifyKeyAttestation]. Useful to match against in-transit attestation processes.
 * Most probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * **Implementing this function in a meaningful manner is absolutely crucial**, since this is the actual challenge
 * matching, ensuring freshness!
 */
typealias ChallengeValidator = suspend (ByteArray) -> ChallengeValidationResult

sealed class ChallengeValidationResult {
    object Success : ChallengeValidationResult()
    class Failure(val reason: Throwable?) : ChallengeValidationResult()
}


/**
 * Gets passed the signed CSR from the mobile client after it was thoroughly checked and verified.
 * At this point, the CSR's signature has been verified, then challenge checked, and the public key attested.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuer = suspend (Pkcs10CertificationRequest) -> KmmResult<CertificateChain>

sealed class PreAttestationError {
    abstract val throwable: Throwable?

    class ChallengeExtraction(override val throwable: Throwable) : PreAttestationError()
    class ChallengeVerification(
        override val throwable: Throwable?,
        val receivedChallenge: ByteArray
    ) : PreAttestationError()

    class AttestationStatementExtraction(override val throwable: Throwable, val csr: Pkcs10CertificationRequest) :
        PreAttestationError()

    class OperationalError(override val throwable: Throwable) : PreAttestationError()
}