package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.attestation.supreme.AttestationResponse.Failure.Type
import at.asitplus.attestation.supreme.PreAttestationError.ChallengeVerification
import at.asitplus.catching
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
import java.util.TreeSet
import java.util.TreeMap
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

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
 * [maxAttestationPayloadBytes] the upper bound of payloads exchanged between client and verifier
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
    val maxAttestationPayloadBytes: Int = WardenDefaults.DEFAULT_MAX_ATTESTATION_PAYLOAD_BYTES,
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
        maxAttestationPayloadBytes: Int = WardenDefaults.DEFAULT_MAX_ATTESTATION_PAYLOAD_BYTES,
        nonceGenerator: NonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(64)) },
        challengeValidator: ChallengeValidator = InMemoryChallengeCache(clock, -verificationTimeOffset),
    ) : this(
        Makoto(androidAttestationConfiguration, iosAttestationConfiguration, clock, verificationTimeOffset),
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        nonceValidity,
        maxAttestationPayloadBytes,
        nonceGenerator,
        challengeValidator,
    )

    init {
        require(maxAttestationPayloadBytes > 0) { "maxAttestationPayloadBytes must be greater than zero" }
    }

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
     * The issued challenge nonce is sensitive replay-protection material. Treat it as a bearer value for the lifetime of
     * the challenge: do not log it, do not expose it across sessions or callers, serve it only over protected transport,
     * and keep caller/session binding and rate limiting in the surrounding HTTP layer if your service needs it.
     *
     * @throws Throwable For example, [InMemoryChallengeCache.ChallengeCacheFullException] is thrown if the default in-memory cache is full. Custom
     * [ChallengeValidator] implementations may throw their own operational exceptions from [ChallengeValidator.store].
     */
    @Throws(Throwable::class)
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
     * [onChallengeValidated] allows side-effect-free investigating/logging/handling of validated challenges.
     * Includes the CSR from the client.
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
     * [additionalVerifications] allows to tighten attestation constraints even more. If any custom checks fail, it should return an
     * [AttestationResponse.Failure], on success it should return null. The reason for this design is to allow additional checks to define their own semantics
     * for specific failure reasons. It *should* not throw (but should an exception bubble up, it will be mapped to an internal error).
     * Don't make your checks throw, unless you want internal errors to hit the end-users.
     *
     * Should any verification step fail, an [AttestationResponse.Failure] is returned.
     *
     * Any exception thrown by the observation callback lambdas is ignored (treated as if the callback were a NOOP).
     * [additionalVerifications] is policy logic, not an observation callback, so exceptions from it cause an internal failure to be sent as response.
     */
    @OptIn(ExperimentalStdlibApi::class)
    suspend fun verifyAttestation(
        csr: Pkcs10CertificationRequest,
        onChallengeValidated: suspend AttestationChallenge.(Pkcs10CertificationRequest) -> Unit = { },
        onPreAttestationError: suspend PreAttestationError.() -> String? = { null },
        onAttestationError: suspend AttestationResult.Error.(debugInfo: WardenDebugAttestationStatement) -> String? = { null },
        onAttestationSuccess: suspend AttestationResult.Verified.(CryptoPublicKey) -> Unit = { },
        additionalVerifications: suspend AttestationChallenge.(Pkcs10CertificationRequest, AttestationResult.Verified) -> AttestationResponse.Failure? = { _, _ -> null },
        certificateIssuer: CertificateIssuer,
    ): AttestationResponse {


        val validatedChallenge = when (val challengeValidationResult = challengeValidator.validate(csr)) {
            is ChallengeValidationResult.Failure.NonceExtraction -> return Failure(
                Type.CONTENT,
                challengeValidationResult.reason.challengeReason(onPreAttestationError)
            )

            is ChallengeValidationResult.Failure.Other ->
                return Failure(Type.CONTENT, challengeValidationResult.reason(csr.tbsCsr, onPreAttestationError))


            is ChallengeValidationResult.Success -> {
                catchingUnwrapped { challengeValidationResult.validatedChallenge.onChallengeValidated(csr) }
                challengeValidationResult.validatedChallenge
            }
        }


        val attestationStatement = csr.tbsCsr.attestationStatementForOid(attestationProofOID).getOrElse {
            return Failure(Type.CONTENT, it.extractionReason(csr, onPreAttestationError))
        }

        with(makoto) {
            return verifyKeyAttestation(attestationStatement, validatedChallenge.nonce).foldTyped(
                onError = {
                    val explanation =
                        it.extractReason(onAttestationError, attestationStatement, validatedChallenge.nonce)
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
                                return Failure(
                                    Type.TRUST,
                                    csrReason(onAttestationError, attestationStatement, validatedChallenge.nonce)
                                )
                            }
                        }
                    }.onFailure {
                        return Failure(Type.INTERNAL, it.operationalReason(onPreAttestationError))
                    }

                    //if additional checks fail, we error out
                    catchingUnwrapped {
                        validatedChallenge.additionalVerifications(csr, details)?.let { return it }
                    }.getOrElse { return AttestationResponse.Failure(Type.INTERNAL, "Custom checks failed") }

                    catchingUnwrapped { details.certificateIssuer(csr) }.fold(
                        onSuccess = {
                            catchingUnwrapped {
                                details.onAttestationSuccess(pubKey.toCryptoPublicKey().getOrThrow()/*TODO mlDSA once Signum supports it*/)
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

    private suspend fun csrReason(
        onAttestationError: suspend AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        AttestationResult.Error(
            "CSR signature verification failed",
            AttestationException.Content.Unknown("CSR signature verification failed", IllegalArgumentException())
        ).onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()

    private suspend fun Throwable.operationalReason(
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.OperationalError(this).onPreAttestationError()
    }.getOrNull()

    private suspend fun AttestationResult.Error.extractReason(
        onAttestationError: suspend AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()

    private suspend fun Throwable.challengeReason(
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.ChallengeExtraction(this).onPreAttestationError()
    }.getOrNull()

    private suspend fun ChallengeValidationResult.Failure.reason(
        tbsCsr: TbsCertificationRequest,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        ChallengeVerification(reason, tbsCsr).onPreAttestationError()
    }.getOrNull()

    private suspend fun Throwable.extractionReason(
        csr: Pkcs10CertificationRequest,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
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
                maxAttestationPayloadBytes = configuration.maxAttestationPayloadBytes,
                nonceGenerator = nonceGenerator,
                challengeValidator = challengeValidator(
                    configuration.clock.timeSource,
                    -makoto.verificationTimeOffset
                ),
            )
        }
    }
}

/** Decodes an HTTP attestation-proof payload after enforcing [AttestationVerifier.maxAttestationPayloadBytes]. */
fun AttestationVerifier.decodeAttestationProof(payload: ByteArray): KmmResult<Pkcs10CertificationRequest> = catching {
    require(payload.size <= maxAttestationPayloadBytes) {
        "Attestation payload exceeds $maxAttestationPayloadBytes bytes"
    }
    Pkcs10CertificationRequest.decodeFromDer(payload)
}


/**
 * Invoked from [AttestationVerifier.verifyAttestation]. Useful to match against in-transit attestation processes.
 * Most probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * **Implementing this function in a meaningful manner is absolutely crucial**, since this is the actual challenge
 * matching, ensuring freshness!
 * Challenge nonces are sensitive replay-protection material: implementations and operators should avoid logging them,
 * avoid exposing them across sessions or callers, and rely on protected transport plus caller-aware controls outside the
 * nonce cache when needed.
 *
 * **BEWARE OF CLOCK DRIFT AND CONFIGURED OFFSETS WRT. VALIDITY DURATION!**
 *
 * @see InMemoryChallengeCache for a sane default logic to account for clock drift
 */
interface ChallengeValidator {
    /**
     * The contract of this function is that it stores challenges regardless of their contents and performs no sanity checks.
     * Reason: Strong cryptographic nonces are assumed, making collisions unrealistic
     *
     * Implementations may throw if they cannot store the challenge. For example, [InMemoryChallengeCache] throws
     * [InMemoryChallengeCache.ChallengeCacheFullException] when its bounded in-memory capacity is exhausted.
     */
    @Throws(InMemoryChallengeCache.ChallengeCacheFullException::class)
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


/** Generates a fresh challenge nonce. */
typealias NonceGenerator = suspend () -> ByteArray

/** Result of matching and consuming the challenge referenced by received client data. */
sealed class ChallengeValidationResult {
    /** Contains the exact previously issued challenge matched by the validator. */
    class Success(val validatedChallenge: AttestationChallenge) : ChallengeValidationResult()

    /** Challenge matching failed for [reason]. */
    sealed class Failure(val reason: Throwable) : ChallengeValidationResult() {
        /** The nonce could not be extracted from the received TBS CSR. */
        class NonceExtraction(reason: Throwable) : Failure(reason)

        /** The nonce was extracted, but no acceptable issued challenge was found or consumed. */
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
 *
 * The cache is bounded by [maxChallenges] and throws [InMemoryChallengeCache.ChallengeCacheFullException] from [store]
 * when that many unexpired challenges are already in flight. Expired entries are pruned before the capacity check and a
 * duplicate nonce overwrites the existing entry even at capacity.
 *
 * Production deployments should apply caller-aware rate limiting outside this cache and may prefer a distributed
 * TTL-backed [ChallengeValidator] when multiple verifier instances are used. The cache deliberately owns no backoff
 * state, because backoff needs caller identity, IP, account, or device context.
 *
 * @throws IllegalArgumentException if [maxChallenges] is not positive.
 */
//internal props for testing
class InMemoryChallengeCache
@Throws(IllegalArgumentException::class)
constructor(
    internal val clock: Clock,
    internal val offset: Duration,
    val maxChallenges: Int = DEFAULT_MAX_IN_MEMORY_CHALLENGES,
) : ChallengeValidator {

    companion object {
        const val DEFAULT_MAX_IN_MEMORY_CHALLENGES: Int = 100_000
    }

    class ChallengeCacheFullException(val maxChallenges: Int) :
        IllegalStateException("In-memory challenge cache full: $maxChallenges challenges in flight")

    init {
        require(maxChallenges > 0) { "maxChallenges must be positive" }
    }

    private val mutex = Mutex()

    private class ChallengeEntry(val nonce: ByteArray, val challenge: AttestationChallenge)

    private val challengesByNonce = TreeMap<ByteArray, ChallengeEntry>(::compareUnsigned)
    private val challengesByExpiry = TreeSet<ChallengeEntry> { left, right ->
        val expiry = left.challenge.validUntil.compareTo(right.challenge.validUntil)
        if (expiry != 0) expiry else compareUnsigned(left.nonce, right.nonce)
    }

    @Throws(ChallengeCacheFullException::class)
    override suspend fun store(challenge: AttestationChallenge) {
        mutex.withLock {
            pruneExpiredEntries()
            val nonce = challenge.nonce
            if (!challengesByNonce.containsKey(nonce) && challengesByNonce.size >= maxChallenges) {
                throw ChallengeCacheFullException(maxChallenges)
            }
            // Strong cryptographic nonces make collisions unrealistic, so we simply overwrite
            challengesByNonce.remove(nonce)?.let(challengesByExpiry::remove)
            ChallengeEntry(nonce, challenge).also {
                challengesByNonce[nonce] = it
                challengesByExpiry += it
            }
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
        val entry = challengesByNonce.remove(nonce) ?: return ChallengeValidationResult.Failure.Other(
            IllegalStateException("No challenge found")
        )
        challengesByExpiry.remove(entry)

        // With a Map, you can't have multiple active entries for the same nonce
        // unless you deliberately store a collection. Given strong random nonces,
        // we assume at most one.
        return ChallengeValidationResult.Success(entry.challenge)
    }

    private fun pruneExpiredEntries() {
        // Capture time once per call instead of per-entry
        val nowWithOffset = clock.now() + offset

        while (challengesByExpiry.isNotEmpty() && challengesByExpiry.first().challenge.validUntil <= nowWithOffset) {
            val entry = challengesByExpiry.pollFirst()
            if (challengesByNonce[entry.nonce] === entry) challengesByNonce.remove(entry.nonce)
        }
    }

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        var index = 0
        while (index < minOf(left.size, right.size)) {
            val result = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
            if (result != 0) return result
            index++
        }
        return left.size.compareTo(right.size)
    }
}
