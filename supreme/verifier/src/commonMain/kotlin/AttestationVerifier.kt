package at.asitplus.attestation.supreme

import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.attestation.supreme.PreAttestationError.ChallengeVerification
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.TimeZone
import org.kotlincrypto.random.CryptoRand
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime

@Deprecated("Misnomer; to be removed in 1.0.0", replaceWith = ReplaceWith("AttestationVerifier"))
typealias AttestationValidator = AttestationVerifier

/**
 * Verifies attestation statements and issues certificates on success.
 * Expects a preconfigured [Makoto] instance defining which apps and devices are considered trustworthy.
 *
 * The [attestationProofOID] to be used in a CSR to convey an attestation statement. Can be overridden. It defaults to [WardenDefaults.OIDs.ATTESTATION_PROOF]
 * When [defaultKeyConstraints] is specified, all issued challenges will automatically convey this, unless overridden.
 * **Note that key constraints cannot be reliably enforced** due to technical client limitations. Not all platforms can restrict key usage and properties!
 *
 * [includeGenericDeviceName] indicates whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16") with the attestation proof.
 * On its own, this is **not the device's nickname and therefore cannot identify a person in its own**.
 * Defaults to `true` as it is very useful technical, **non-personally-identifying data**.
 *
 *
 * If your app relies on Warden Supreme, they will be respected, though, but there is no cryptography-backed enforcement.
 * Also requires a [challengeValidator], checking challenges validity and invalidating it once used.
 */
class AttestationVerifier(
    private val makoto: Makoto,
    val attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
    val includeGenericDeviceName: Boolean = true,
    val defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    val defaultNonceValidity: Duration = WardenDefaults.nonceValidity,
    private val nonceGenerator: NonceGenerator = WardenDefaults.nonceGenerator,
    private val challengeValidator: ChallengeValidator = InMemoryChallengeCache(makoto.clock)
) {
    /**
     *
     * @param androidAttestationConfiguration Configuration for Android key attestation.
     * See [AndroidAttestationConfiguration]
     * for details.
     * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param attestationProofOID specifies the OID be used in a CSR to convey an attestation statement. Can be overridden. It defaults to [WardenDefaults.OIDs.ATTESTATION_PROOF].
     * @param includeGenericDeviceName specifies Whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16" with the attestation proof).
     * On its own, this is **not the device's nickname and therefore cannot identify a person in its own**.
     * Defaults to `true` as it is very useful technical, **non-personally-identifying data**.
     * @param clock a clock to set the time of verification (used for certificate validity checks)
     * @param verificationTimeOffset allows for fine-grained clock drift compensation (this duration is added to the certificate
     * @param defaultKeyConstraints allows for specifying key constraints to the client. Not all platforms can restrict key usage and properties!
     * @param challengeValidator lambda checking challenges validity and invalidating it once used
     * validity checks); can be negative.
     */
    @OptIn(ExperimentalTime::class)
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        iosAttestationConfiguration: IosAttestationConfiguration,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        includeGenericDeviceName: Boolean = true,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = Duration.ZERO,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
        defaultNonceValidity: Duration = WardenDefaults.nonceValidity,
        nonceGenerator: NonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(64)) },
        challengeValidator: ChallengeValidator = InMemoryChallengeCache(clock)
    ) : this(
        Makoto(androidAttestationConfiguration, iosAttestationConfiguration, clock, verificationTimeOffset),
        attestationProofOID,
        includeGenericDeviceName,
        defaultKeyConstraints,
        defaultNonceValidity,
        nonceGenerator,
        challengeValidator,
    )

    /**
     * Alias for [makoto]
     */
    @Deprecated("Misnomer; to be removed in 1.0.0", replaceWith = ReplaceWith("makoto"))
    val warden: Makoto get() = makoto

    /**
     * Issues a new attestation challenge, using a nonce generated by [nonceGenerator], valid for a duration of [validity], expecting an CSR containing an attestation statement to be `HTTP POST`ed to [postEndpoint].
     * It is recommended, to pass a [timeZone].
     *
     * Specify [keyConstraints] to communicate to the type of key and its properties to the client, for automatic key creation. Defaults to [defaultKeyConstraints].
     *
     * It is possible to pass [timeZone] info and a [timeOffset] to account for an incorrect server clock. This value is added to the returned [AttestationChallenge.issuedAt] and accounted for when calculating [AttestationChallenge.validUntil].
     */
    suspend fun issueChallenge(
        postEndpoint: String,
        validity: Duration = defaultNonceValidity,
        timeZone: TimeZone? = null,
        timeOffset: Duration = Duration.ZERO,
        keyConstraints: KeyConstraints? = defaultKeyConstraints
    ) =
        AttestationChallenge(
            issuedAt = makoto.clock.now() + timeOffset,
            validity,
            timeZone,
            nonceGenerator(),
            postEndpoint,
            attestationProofOID,
            includeGenericDeviceName,
            keyConstraints
        ).also { challengeValidator.store(it) }

    /**
     * Verifies the received CSR:
     * * Validates nonce contained in the [csr] against the [challengeValidator]
     * * extracts the attestation statement from the [csr]
     * * calls upon [makoto] for key attestation based on the extracted attestation statement
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
     * Logging and/or collecting numbers for statistical analysis comes to mind.
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

        when (val challengeValidationResult = challengeValidator.validate(nonce)) {
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

            is ChallengeValidationResult.Success -> {} //for now, we don't care for the issued challenge
            //but we may in teh future, e.g. to check whether Key Constraints are actually fulfilled.
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

        val result = makoto.verifyKeyAttestation(attestationStatement, nonce)
        return result.fold(
            onError = {
                val explanation = catchingUnwrapped {
                    it.onAttestationError(
                        makoto.collectDebugInfo(
                            attestationStatement,
                            nonce
                        )
                    )
                }.getOrNull()
                when (it.cause) {
                    null, is AttestationException.Content -> Failure(Failure.Type.CONTENT, explanation)
                    is AttestationException.Certificate.Time -> Failure(Failure.Type.TIME, explanation)
                    is AttestationException.Certificate.Trust -> Failure(Failure.Type.TRUST, explanation)
                    is AttestationException.Configuration -> Failure(Failure.Type.INTERNAL, explanation)
                }
            },
            onSuccess = { pubKey, details ->
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

                catchingUnwrapped {
                    signature.initVerify(pubKey)
                    if (signature.verify(csr.decodedSignature.getOrThrow().jcaSignatureBytes)) {
                        val explanation = catchingUnwrapped {
                            AttestationResult.Error("CSR signature verification failed")
                                .onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
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

                catchingUnwrapped { certificateIssuer.invoke(csr, details) }.fold(
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
 * Invoked from [AttestationVerifier.verifyKeyAttestation]. Useful to match against in-transit attestation processes.
 * Most probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * **Implementing this function in a meaningful manner is absolutely crucial**, since this is the actual challenge
 * matching, ensuring freshness!
 */
interface ChallengeValidator {
    suspend fun store(challenge: AttestationChallenge)
    suspend fun validate(nonce: ByteArray): ChallengeValidationResult
}

/**
 *
 */
typealias NonceGenerator = suspend () -> ByteArray

sealed class ChallengeValidationResult {
    class Success(val validatedChallenge: AttestationChallenge) : ChallengeValidationResult()
    class Failure(val reason: Throwable?) : ChallengeValidationResult()
}


/**
 * Gets passed the signed CSR from the mobile client after it was thoroughly checked and verified.
 * At this point, the CSR's signature has been verified, then challenge checked, and the public key attested.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuer = suspend (Pkcs10CertificationRequest, AttestationResult.Verified) -> CertificateChain

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

class InMemoryChallengeCache(private val clock: Clock) : ChallengeValidator {

    private val mutex = Mutex()
    private val challengeList = mutableListOf<AttestationChallenge>()

    override suspend fun store(challenge: AttestationChallenge) {
        mutex.withLock {
            pruneExpiredEntries()
            challengeList.add(challenge)
        }
    }

    override suspend fun validate(nonce: ByteArray): ChallengeValidationResult {
        mutex.withLock {
            pruneExpiredEntries()
            val ind = challengeList.indexOfFirst { it.nonce.contentEquals(nonce) }
            return if (ind == -1) ChallengeValidationResult.Failure(IllegalStateException("No challenge found"))
            else ChallengeValidationResult.Success(challengeList.removeAt(ind))

        }
    }

    private fun pruneExpiredEntries() {
        for (i in challengeList.indices.reversed()) {
            if (challengeList[i].validUntil <= clock.now()) {
                challengeList.removeAt(i)
            }
        }
    }


}