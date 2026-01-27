package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.attestation.supreme.AttestationResponse.Failure.Type
import at.asitplus.attestation.supreme.PreAttestationError.ChallengeVerification
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.TimeZone
import org.kotlincrypto.random.CryptoRand
import java.security.Signature
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * Verifies attestation statements and issues certificates on success.
 * Expects a preconfigured [Makoto] instance defining which apps and devices are considered trustworthy.
 *
 * The [attestationProofOID] to be used in a CSR to convey an attestation statement. Can be overridden. It defaults to [WardenDefaults.OIDs.ATTESTATION_PROOF]
 * When [defaultKeyConstraints] is specified, all issued challenges will automatically convey this, unless overridden.
 * **Note that key constraints cannot be reliably enforced** due to technical client limitations. Not all platforms can restrict key usage and properties!
 * Still, Warden Supreme's client will respect the key constraints and create keys as specified.
 *
 * [genericDeviceNameOID] indicates whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16") with the attestation proof.
 * On its own, this is **not the device's nickname and therefore cannot identify a person in its own**.
 * Defaults to [WardenDefaults.OIDs.DEVICE_NAME] as it is very useful technical, **non-personally-identifying data**.
 * Can be set to `null` to not include device names.
 *
 * The [nonceGenerator]'s responsibility is to generate nonces to ensure freshness of issues challenges. Defaults to [WardenDefaults.nonceGenerator],
 * which generates secure, random 64-byte nonces
 *
 * [nonceValidity] indicates how long issued nonces remain valid. This defaults to the maximum of the passed [makoto]'s
 * [IosAttestationConfiguration.attestationStatementValiditySeconds] and [AndroidAttestationConfiguration.attestationStatementValiditySeconds].
 *
 */

class AttestationVerifier
@Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
constructor(
    val makoto: Makoto,
    val attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
    val genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
    val defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    val nonceValidity: Duration = makoto.longestValidityDuration
        ?: IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS.seconds,
    private val nonceGenerator: NonceGenerator = WardenDefaults.nonceGenerator,
    /*internal for testing*/
    internal val challengeValidator: ChallengeValidator = InMemoryChallengeCache(
        makoto.clock,
        -makoto.verificationTimeOffset
    ),
) {

    @Deprecated(
        "Use `SupremeConfiguration` instead. To be removed in 1.1 due to inherent footguns",
        level = DeprecationLevel.ERROR
    )
    @OptIn(ExperimentalTime::class)
    @Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        iosAttestationConfiguration: IosAttestationConfiguration,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
        nonceValidity: Duration = Makoto.longestDuration(
            iosAttestationConfiguration.attestationStatementValiditySeconds,
            androidAttestationConfiguration.attestationStatementValiditySeconds
        ),
        nonceGenerator: NonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(64)) },
        challengeValidator: ChallengeValidator = InMemoryChallengeCache(clock, -verificationTimeOffset),
    ) : this(
        Makoto(androidAttestationConfiguration, iosAttestationConfiguration, clock, verificationTimeOffset),
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        nonceValidity,
        nonceGenerator,
        challengeValidator,
    )

    /**
     * Issues a new attestation challenge, using a nonce generated by [nonceGenerator], valid for a duration of [nonceValidity], expecting an CSR containing an attestation statement to be `HTTP POST`ed to [postEndpoint].
     * It is possible, to pass a [timeZone], but this is purely informational and is not fed into validity checks.
     *
     * Specify [keyConstraints] to communicate to the type of key and its properties to the client, for automatic key creation. Defaults to [defaultKeyConstraints].
     *
     * Note that the inverse of [Makoto.verificationTimeOffset] is added to the nonce validity period to account for clock drift between clients and server.
     * Why the inverse? Because clients check validity against their local clocks, reversing their relative view of the server time offset.
     *
     * **Note that the [challengeValidator] needs to account for this inverse view! The default [InMemoryChallengeCache] already does that.**
     *
     *
     */
    suspend fun issueChallenge(
        postEndpoint: String,
        timeZone: TimeZone? = null,
        keyConstraints: KeyConstraints? = defaultKeyConstraints,
    ) = AttestationChallenge(
        issuedAt = makoto.clock.now() - makoto.verificationTimeOffset,
        nonceValidity,
        timeZone,
        nonceGenerator(),
        postEndpoint,
        attestationProofOID,
        genericDeviceNameOID,
        keyConstraints
    ).also { challengeValidator.store(it) }


    /**
     * Verifies the received CSR:
     * * Validates nonce contained in the [csr] against the [challengeValidator]
     * * extracts the attestation statement from the [csr]
     * * calls upon [makoto] for key and app attestation based on the extracted attestation statement
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
    suspend fun verifyAttestation(
        csr: Pkcs10CertificationRequest,
        onPreAttestationError: PreAttestationError.() -> String? = { null },
        onAttestationError: AttestationResult.Error.(debugInfo: WardenDebugAttestationStatement) -> String? = { null },
        onAttestationSuccess: AttestationResult.Verified.(CryptoPublicKey) -> Unit = { },
        certificateIssuer: CertificateIssuer,
    ): AttestationResponse {


        val nonce = when (val challengeValidationResult = challengeValidator.validate(csr)) {
            is ChallengeValidationResult.Failure.NonceExtraction -> return Failure(
                Type.CONTENT,
                challengeValidationResult.reason.challengeReason(onPreAttestationError)
            )

            is ChallengeValidationResult.Failure.Other ->
                return Failure(Type.CONTENT, challengeValidationResult.reason(csr.tbsCsr, onPreAttestationError))


            is ChallengeValidationResult.Success -> {
                challengeValidationResult.validatedChallenge.nonce
            } //for now, we don't care for the issued challenge
            //but we may in teh future, e.g. to check whether Key Constraints are actually fulfilled.
        }

        val attestationStatement = csr.tbsCsr.attestationStatementForOid(attestationProofOID).getOrElse {
            return Failure(Type.CONTENT, it.extractionReason(csr, onPreAttestationError))
        }

        with(makoto) {
            return verifyKeyAttestation(attestationStatement, nonce).foldTyped(
                onError = {
                    val explanation = it.extractReason(onAttestationError, attestationStatement, nonce)
                    when (it.cause) {
                        is AttestationException.Certificate.Time -> Failure(Type.TIME, explanation)
                        is AttestationException.Content -> when (it.cause as AttestationException.Content) {
                            is AttestationException.Content.Android -> when ((it.cause as AttestationException.Content.Android).cause.reason) {
                                AttestationValueException.Reason.STATEMENT_TIME -> Failure(Type.TIME, explanation)
                                else -> Failure(Type.CONTENT, explanation)
                            }

                            is AttestationException.Content.iOS -> when ((it.cause as AttestationException.Content.iOS).cause.reason) {
                                IosAttestationException.Reason.STATEMENT_TIME -> Failure(Type.TIME, explanation)
                                else -> Failure(Type.CONTENT, explanation)
                            }

                            else -> Failure(Type.CONTENT, explanation)
                        }

                        is AttestationException.Certificate.Trust -> Failure(Type.TRUST, explanation)
                        is AttestationException.Configuration -> Failure(Type.CONTENT, explanation)
                    }
                },
                onSuccess = { pubKey, details ->
                    catchingUnwrapped {
                        csr.jcaSignature().getOrThrow().apply {
                            initVerify(pubKey)
                            update(csr.tbsCsr.encodeToDer())
                            if (!verify(csr.decodedSignature.getOrThrow().jcaSignatureBytes)) {
                                return Failure(Type.TRUST, csrReason(onAttestationError, attestationStatement, nonce))
                            }
                        }
                    }.onFailure {
                        return Failure(Type.INTERNAL, it.operationalReason(onPreAttestationError))
                    }

                    catchingUnwrapped { details.certificateIssuer(csr) }.fold(
                        onSuccess = {
                            catchingUnwrapped {
                                details.onAttestationSuccess(pubKey.toCryptoPublicKey().getOrThrow()/*TODO*/)
                            }
                            AttestationResponse.Success(it)
                        },
                        onFailure = {
                            Failure(Type.INTERNAL, it.operationalReason(onPreAttestationError))
                        }
                    )
                }
            )
        }
    }

    private fun Pkcs10CertificationRequest.jcaSignature(): KmmResult<Signature> =
        (signatureAlgorithm as SpecializedSignatureAlgorithm).getJCASignatureInstance()

    private fun csrReason(
        onAttestationError: AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        AttestationResult.Error(
            "CSR signature verification failed",
            AttestationException.Content.Unknown("CSR signature verification failed", IllegalArgumentException())
        ).onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()

    private fun Throwable.operationalReason(
        onPreAttestationError: PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.OperationalError(this).onPreAttestationError()
    }.getOrNull()

    private fun AttestationResult.Error.extractReason(
        onAttestationError: AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()

    private fun Throwable.challengeReason(
        onPreAttestationError: PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.ChallengeExtraction(this).onPreAttestationError()
    }.getOrNull()

    private fun ChallengeValidationResult.Failure.reason(
        tbsCsr: TbsCertificationRequest,
        onPreAttestationError: PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        ChallengeVerification(reason, tbsCsr).onPreAttestationError()
    }.getOrNull()

    private fun Throwable.extractionReason(
        csr: Pkcs10CertificationRequest,
        onPreAttestationError: PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.AttestationStatementExtraction(this, csr).onPreAttestationError()
    }.getOrNull()

    companion object {
        /**
         * Configures and initializes an [AttestationVerifier] using the provided configuration, nonce generator, and challenge
         * verifier.
         *
         * Note that the nonce validity will always be the longest validity duration over [SupremeConfiguration.android] and [SupremeConfiguration.ios].
         * If only an Android configuration without a nonce validity duration is provided, this will default to [IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS].
         *
         * @param configuration The [SupremeConfiguration] object containing Android and/or iOS attestation configurations, attestation proof OID,
         * generic device name OID, default key constraints, and verification time offset.
         * @param nonceGenerator A [NonceGenerator] instance to generate unique challenges for verification. Defaults to [WardenDefaults.nonceGenerator].
         * @param challengeValidator A lambda function that initializes a [ChallengeValidator] based on:
         *  * the provided [SupremeConfiguration.Clock.timeSource]
         *  * the **inverse** [SupremeConfiguration.verificationTimeOffset] because drift in the opposite direction relative to the back end.
         *    Passing the inverse here means straight-forward challenge validation logic without the need to account for who sees what inverted and who doesn't.
         *
         * [configuration].
         * Defaults to using an [InMemoryChallengeCache].
         * @return An instance of [AttestationVerifier] configured with the provided parameters.
         */
        operator fun invoke(
            configuration: SupremeConfiguration,
            nonceGenerator: NonceGenerator = WardenDefaults.nonceGenerator,
            challengeValidator: (Clock, Duration) -> ChallengeValidator = { clock, verificationTimeOffset ->
                InMemoryChallengeCache(clock, verificationTimeOffset)
            }
        ): AttestationVerifier = Makoto(configuration).let { makoto ->
            AttestationVerifier(
                makoto,
                attestationProofOID = configuration.attestationProofOID,
                genericDeviceNameOID = configuration.genericDeviceNameOID,
                defaultKeyConstraints = configuration.defaultKeyConstraints,
                nonceValidity = makoto.longestValidityDuration
                    ?: IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS.seconds,
                nonceGenerator = nonceGenerator,
                challengeValidator = challengeValidator(
                    configuration.clock.timeSource,
                    -makoto.verificationTimeOffset
                ),
            )
        }
    }
}

/**
 * Invoked from [AttestationVerifier.verifyAttestation]. Useful to match against in-transit attestation processes.
 * Most probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * **Implementing this function in a meaningful manner is absolutely crucial**, since this is the actual challenge
 * matching, ensuring freshness!
 *
 * **BEWARE OF CLOCK DRIFT AND CONFIGURED OFFSETS WRT. VALIDITY DURATION!**
 *
 * @see InMemoryChallengeCache for a sane default logic to account for clock drift
 */
interface ChallengeValidator {
    /**
     * The contract of this function is that it stores challenges regardless of their contents and performs no sanity checks.
     * Reason: Strong cryptographic nonces are assumed, making collisions unrealistic
     */
    suspend fun store(challenge: AttestationChallenge)

    /**
     * The contract of this function is that it returns a [ChallengeValidationResult.Success] iff a valid
     * challenge matching the passend [csr] from the client is found.
     * In all other cases, it must return a [ChallengeValidationResult.Failure]:
     * * It must return a [ChallengeValidationResult.Failure.NonceExtraction] if nonce extraction fails (relevant for nonce-cache based implementations)
     * * It must return a [ChallengeValidationResult.Failure.Other] if other validation errors occur, such as no valid challenge matching the passed  [csr].
     * In addition, it **should** also remove all expired challenges, to keep stale challenges from inflating memory/storage.
     */
    suspend fun validate(csr: Pkcs10CertificationRequest): ChallengeValidationResult
}


/**
 *
 */
typealias NonceGenerator = suspend () -> ByteArray

sealed class ChallengeValidationResult {
    class Success(val validatedChallenge: AttestationChallenge) : ChallengeValidationResult()
    sealed class Failure(val reason: Throwable) : ChallengeValidationResult() {
        class NonceExtraction(reason: Throwable) : Failure(reason)
        class Other(reason: Throwable) : Failure(reason)
    }
}


/**
 * Gets passed the signed CSR from the mobile client after it was thoroughly checked and verified.
 * At this point, the CSR's signature has been verified, then challenge checked, and the public key attested.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuer = suspend AttestationResult.Verified.(Pkcs10CertificationRequest) -> CertificateChain

sealed class PreAttestationError {
    abstract val throwable: Throwable?

    class ChallengeExtraction(override val throwable: Throwable) : PreAttestationError()
    class ChallengeVerification(
        override val throwable: Throwable?,
        val receivedTbsCsr: TbsCertificationRequest,
    ) : PreAttestationError()

    class AttestationStatementExtraction(override val throwable: Throwable, val csr: Pkcs10CertificationRequest) :
        PreAttestationError()

    class OperationalError(override val throwable: Throwable) : PreAttestationError()
}


/**
 * Caches issued challenges in memory in a coroutine-safe way. Requires a [clock] and an [offset].
 * The [AttestationVerifier] passes [Makoto]'s clock and the inverse of [Makoto.verificationTimeOffset], since these two values
 * are also encoded into issues challenges.
 */
//internal props for testing
class InMemoryChallengeCache(internal val clock: Clock, internal val offset: Duration) : ChallengeValidator {

    private val mutex = Mutex()

    /**
     * Use a hash map keyed by nonce instead of a list to make lookups O(1) instead of O(n).
     * ByteArray is not suitable as a key directly, so we wrap it.
     */
    private class NonceKey(val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean =
            this === other || (other is NonceKey && bytes.contentEquals(other.bytes))

        override fun hashCode(): Int = bytes.contentHashCode()
        override fun toString(): String = bytes.toHexString()
    }

    private val challengesByNonce = mutableMapOf<NonceKey, AttestationChallenge>()

    override suspend fun store(challenge: AttestationChallenge) {
        mutex.withLock {
            pruneExpiredEntries()
            // Strong cryptographic nonces make collisions unrealistic, so we simply overwrite
            challengesByNonce[NonceKey(challenge.nonce)] = challenge
        }
    }

    override suspend fun validate(csr: Pkcs10CertificationRequest): ChallengeValidationResult {
        mutex.withLock {
        val nonce = csr.tbsCsr.nonce.getOrElse {
            return ChallengeValidationResult.Failure.NonceExtraction(it)
        }
            pruneExpiredEntries()
            return find(nonce)
        }
    }

    private fun find(nonce: ByteArray): ChallengeValidationResult {
        val key = NonceKey(nonce)
        val challenge = challengesByNonce.remove(key) ?: return ChallengeValidationResult.Failure.Other(
            IllegalStateException("No challenge found")
        )

        // With a Map, you can't have multiple active entries for the same nonce
        // unless you deliberately store a collection. Given strong random nonces,
        // we assume at most one.
        return ChallengeValidationResult.Success(challenge)
    }

    private fun pruneExpiredEntries() {
        // Capture time once per call instead of per-entry
        val nowWithOffset = clock.now() + offset

        val iterator = challengesByNonce.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.validUntil <= nowWithOffset) {
                iterator.remove()
            }
        }
    }
}
