@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.Makoto.Companion.assertionReader
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.toJcaPublicKey
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.assertion.AssertionChallengeValidator
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import kotlinx.coroutines.runBlocking
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import kotlin.time.ExperimentalTime
import at.asitplus.attestation.AttestationException as AttException

abstract class AttestationService {


    internal abstract suspend fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray? = null
    ): AttestationResult

    @JvmName("verifyKeyAttestation")
    fun verifyKeyAttestationBlocking(attestationProof: Attestation, challenge: ByteArray): KeyAttestation<PublicKey> =
        runBlocking { doVerifyKeyAttestation(attestationProof, challenge) }

    @JvmName("verifyKeyAttestationSuspending")
    suspend fun verifyKeyAttestation(attestationProof: Attestation, challenge: ByteArray): KeyAttestation<PublicKey> =
        doVerifyKeyAttestation(attestationProof, challenge)

    protected abstract suspend fun doVerifyKeyAttestation(
        attestationProof: Attestation,
        challenge: ByteArray
    ): KeyAttestation<PublicKey>

    /**
     * Verifies key attestation for both Android and Apple devices.
     *
     * Succeeds if attestation data structures of the client (in [attestationProof]) can be verified and [expectedChallenge] matches
     * the attestation challenge. For Android clients, this function makes sure that [keyToBeAttested] matches the key contained in the attestation certificate.
     * For iOS this key needs to be specified explicitly anyhow to emulate key attestation
     *
     * @param attestationProof On Android, this is simply the certificate chain from the attestation certificate
     * (i.e. the certificate corresponding to the key to be attested) up to one of the [Google hardware attestation root
     * certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
     * on iOS this must contain the [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
     * at index `0` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * at index `1`, which, is verified for integrity and to match [keyToBeAttested].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`.
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as `clientData` to create an assertion effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE: supports only EC key on iOS (either the ANSI X9.63 encoded or DER encoded).
     * The key can be passed in either encoding to the secure enclave for assertion/attestation**
     *
     * @param expectedChallenge
     * @param keyToBeAttested
     *
     * @return [KeyAttestation] containing the attested public key on success or null in case of failure (see [KeyAttestation])
     */
    @Deprecated(
        "This uses the legacy attestation format, which is not future-proof, makes too few guarantees wrt. encoding, " +
                "guesses the platform based on the number of elements in the attestation proof, etc.",
        ReplaceWith("verifyKeyAttestation(attestationProof, challenge)")
    )
    @JvmName("verifyKeyAttestation")
    fun <T : PublicKey> verifyKeyAttestationBlocking(
        attestationProof: List<ByteArray>,
        expectedChallenge: ByteArray,
        keyToBeAttested: T
    ): KeyAttestation<T> = runBlocking {
        verifyKeyAttestation(
            attestationProof,
            expectedChallenge,
            keyToBeAttested
        )
    }

    /**
     * Verifies key attestation for both Android and Apple devices.
     *
     * Succeeds if attestation data structures of the client (in [attestationProof]) can be verified and [expectedChallenge] matches
     * the attestation challenge. For Android clients, this function makes sure that [keyToBeAttested] matches the key contained in the attestation certificate.
     * For iOS this key needs to be specified explicitly anyhow to emulate key attestation
     *
     * @param attestationProof On Android, this is simply the certificate chain from the attestation certificate
     * (i.e. the certificate corresponding to the key to be attested) up to one of the [Google hardware attestation root
     * certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate).
     * on iOS this must contain the [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
     * at index `0` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * at index `1`, which, is verified for integrity and to match [keyToBeAttested].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`.
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as `clientData` to create an assertion effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE: supports only EC key on iOS (either the ANSI X9.63 encoded or DER encoded).
     * The key can be passed in either encoding to the secure enclave for assertion/attestation**
     *
     * @param expectedChallenge
     * @param keyToBeAttested
     *
     * @return [KeyAttestation] containing the attested public key on success or null in case of failure (see [KeyAttestation])
     */
    @Deprecated(
        "This uses the legacy attestation format, which is not future-proof, makes too few guarantees wrt. encoding, " +
                "guesses the platform based on the number of elements in the attestation proof, etc.",
        ReplaceWith("verifyKeyAttestation(attestationProof, challenge)")
    )
    @JvmName("verifyKeyAttestationSuspending")
    suspend fun <T : PublicKey> verifyKeyAttestation(
        attestationProof: List<ByteArray>,
        expectedChallenge: ByteArray,
        keyToBeAttested: T
    ): KeyAttestation<T> = keyToBeAttested.transcodeToAllFormats().let { transcended ->
        // try all different key encodings
        // not the most efficient way, but doing it like this won't involve any guesswork at all
        transcended.forEachIndexed { i, it ->
            when (val secondTry =
                catchingUnwrapped { verifyAttestation(attestationProof, expectedChallenge, it) }
                    .getOrElse {
                        val message = it.message ?: it.javaClass.simpleName
                        if (it is AttException) {
                            AttestationResult.Error(message, it)
                        } else AttestationResult.Error(
                            message,
                            AttException.Content.Unknown(message, it)
                        )
                    }.also {
                        if (i == transcended.lastIndex) return KeyAttestation(null, it)
                    }) {
                is AttestationResult.Error -> {} //try again, IOS could have encoded it differently

                //if this works, perfect!
                is AttestationResult.IOS, is AttestationResult.Android -> {
                    return KeyAttestation(
                        keyToBeAttested,
                        secondTry
                    )
                }
            }
        }
        //can never be reached
        throw logicalError(keyToBeAttested, attestationProof, expectedChallenge)
    }

    private fun <T : PublicKey> T.toLogString(): String? = encoded.encodeBase64()

    private fun <T : PublicKey> AttestationException.Content.toAttestationError(it: String): KeyAttestation<T> =
        KeyAttestation(null, AttestationResult.Error(it, this))


    /** Same as [verifyKeyAttestation], but taking an encoded (either ANSI X9.63 or DER) publix key as a byte array
     * @see verifyKeyAttestation
     *
     */
    @Deprecated(
        "This uses the legacy attestation format, which is not future-proof, makes too few guarantees wrt. encoding, " +
                "guesses the platform based on the number of elements in the attestation proof, etc.",
        ReplaceWith("verifyKeyAttestation(attestationProof, challenge)")
    )
    @JvmName("verifyKeyAttestation")
    suspend fun verifyKeyAttestationBlocking(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        encodedPublicKey: ByteArray
    ): KeyAttestation<PublicKey> = verifyKeyAttestation(attestationProof, challenge, encodedPublicKey)

    /** Same as [verifyKeyAttestation], but taking an encoded (either ANSI X9.63 or DER) publix key as a byte array
     * @see verifyKeyAttestation
     */
    @Deprecated(
        "This uses the legacy attestation format, which is not future-proof, makes too few guarantees wrt. encoding, " +
                "guesses the platform based on the number of elements in the attestation proof, etc.",
        ReplaceWith("verifyKeyAttestation(attestationProof, challenge)")
    )
    @JvmName("verifyKeyAttestationSuspending")
    suspend fun verifyKeyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        encodedPublicKey: ByteArray
    ): KeyAttestation<PublicKey> =
        verifyKeyAttestation(attestationProof, challenge, encodedPublicKey.parseToPublicKey())

    /**
     * Groups iOS-specific API to reduce toplevel clutter.
     *
     * Exposes iOS-specific functionality in a more expressive, and less confusing manner
     */
    abstract val ios: IOS

    interface IOS {
        /**
         * convenience method specific to iOS, which only verifies App Attestation and no assertion
         * @param attestationObject the AppAttest attestation object to verify
         * @param challenge the challenge to verify against
         */
        fun verifyAppAttestation(
            attestationObject: ByteArray,
            challenge: ByteArray,
        ): AttestationResult

        /**
         * Verifies an App Attestation in conjunction with an assertion for some client data.
         *
         * First, it verifies the app attestation, afterwards it verifies the assertion, checks whether at most the assertion was the first thing that was signed
         * after attesting the key (i.e. signature counter = `0` before signing the assertion), and verifies whether the client data
         * referenced within the assertion matches [referenceClientData]
         *
         * @param attestationObject the AppAttest attestation object to verify
         * @param assertionFromDevice the assertion data created on the device.
         * @param referenceClientData the expected client data to be contained in [assertionFromDevice]
         */
        fun verifyCombined(
            attestationObject: ByteArray,
            assertionFromDevice: ByteArray,
            referenceClientData: ByteArray,
            challenge: ByteArray,
        ): AttestationResult

        /**
         * Verifies a fresh assertion, tied to a previously stored attestation.
         * This function assumes that `clientDataHash` is the SHA-256 digest of [expectedChallenge].
         *
         * **The attestation is not verified again!**
         * There is no timeliness guarantee of any kind, so manually verify the freshness of the challenge **before**
         * calling this function
         *
         * **A Note on Counters:**<br>
         * AppAttest only checks whether the signature counter **BEFORE SIGNING AN ASSERTION** is _higher_ than a provided value. That is, a value of `0` will always work.
         * Warden Supreme also allows checking for a maximum, hence [validCounters]. If you don't care for it, just pass [Long.MAX_VALUE] as upper bound (inclusive).<br>
         * **Also note that the upper bound will also be calculated on the value _BEFORE_ creating the assertion!**
         *
         * @param validatedAttestation the previously validated attestation
         * @param expectedChallenge the expected client data to be contained in [assertion]
         * @param validCounters The range of valid counters
         */
        @Deprecated(
            "To be removed in Warden Supreme 1.3. Confusing API",
            replaceWith = ReplaceWith("validateAssertionWithChallenge(validatedAttestation, assertion, expectedChallenge, lastSeenCounter = validCounters.first, maxCounter = validCounters.last - 1)")
        )
        fun verifyAssertion(
            validatedAttestation: ValidatedAttestation,
            assertion: ByteArray,
            expectedChallenge: ByteArray,
            validCounters: LongRange
        ): Result<Assertion> = validateAssertionWithChallenge(
            validatedAttestation,
            assertion,
            expectedChallenge,
            lastSeenCounter = validCounters.first,
            maxCounter = if(validCounters.last==Long.MAX_VALUE) Long.MAX_VALUE else validCounters.last + 1
        )

        fun validateAssertionWithChallenge(
            validatedAttestation: ValidatedAttestation,
            assertion: ByteArray,
            expectedChallenge: ByteArray,
            lastSeenCounter: Long,
            maxCounter: Long = Long.MAX_VALUE,
        ): Result<Assertion>

        /**
         * Verifies a fresh assertion, tied to a previously stored attestation.
         *
         * **The attestation is not verified again!**
         * There is no timeliness guarantee of any kind, so manually verify the freshness of the challenge **before**
         * calling this function
         *
         * **A Note on Counters:**<br>
         * AppAttest only checks whether the signature counter is _higher_ than a provided value. That is, a value of `0` will always work.
         * Warden Supreme also allows checking for a maximum, hence [validCounters]. If you don't care for it, just pass [Long.MAX_VALUE] as upper bound (inclusive).<br>
         * **Also note that the upper bound will also be calculated on the value _BEFORE_ creating the assertion!**
         *
         *
         * @param validatedAttestation the previously validated attestation
         * @param validCounters The range of valid counters
         * @param validator a fresh [AssertionChallengeValidator] that checks for challenge, clientData, etc.
         */
        @Deprecated(
            "To be removed in Warden Supreme 1.3. Confusing API",
            replaceWith = ReplaceWith("validator.validateAssertion(validatedAttestation, assertion, referenceClientData = referenceClientData, expectedChallenge = expectedChallenge, lastSeenCounter = validCounters.first, maxCounter = validCounters.last - 1)")
        )
        fun verifyAssertion(
            validatedAttestation: ValidatedAttestation,
            assertion: ByteArray,
            referenceClientData: ByteArray,
            validCounters: LongRange,
            expectedChallenge: ByteArray,
            validator: AssertionChallengeValidator,
        ): Result<Assertion> = with(validator) {
            validateAssertion(
                validatedAttestation,
                assertion,
                referenceClientData = referenceClientData,
                expectedChallenge = expectedChallenge,
                lastSeenCounter = validCounters.first,
                maxCounterAdvance = if(validCounters.last==Long.MAX_VALUE) Long.MAX_VALUE else validCounters.last + 1
            )
        }

        /**
         * Verifies a fresh assertion, tied to a previously stored attestation.
         *
         * **The attestation is not verified again!**
         * There is no timeliness guarantee of any kind, so manually verify the freshness of the challenge **before**
         * calling this function
         *
         * **A Note on Counters:**<br>
         * AppAttest only checks whether the signature counter is _higher_ than *the last seen counter**. That is, a value of `0L` will always work.
         * Warden Supreme also allows specifying how much the counter may at most have advanced since the [lastSeenCounter]
         * (i.e. since the signaure count of the last seen valid assertion), hence [maxCounterAdvance].<br>
         *
         * Example:
         * ```kotlin
         * // calling for the very first time, an assertion is received:
         * with(validator) {
         *   validateAssertion(attestation, assertion, clientData, challenge,
         *     lastSeenCounter = 0L, //No signatures have been created
         *     maxCounterAdvance = 1L //Make sure that this is the first signature to be created
         * }
         * ```
         *
         *
         * @param validator a fresh [AssertionChallengeValidator] that checks for challenge, clientData, etc.
         * @param validatedAttestation the previously validated attestation
         * @param assertion the assertions to validate
         * @param referenceClientData the client data inside the assertion
         * @param expectedChallenge the expected challenge
         * @param lastSeenCounter the counter of the last recorded assertion; the current [assertion] counter must be > [lastSeenCounter]. That is, a value of `0L` will always work.
         * @param maxCounterAdvance the maximum the counter is allowed to have advanced since the last validated assertion.
         */
        context(validator: AssertionChallengeValidator)
        fun validateAssertion(
            validatedAttestation: ValidatedAttestation,
            assertion: ByteArray,
            referenceClientData: ByteArray,
            expectedChallenge: ByteArray,
            lastSeenCounter: Long,
            maxCounterAdvance: Long = Long.MAX_VALUE,
        ): Result<Assertion>
    }

    /**
     * Exposes Android-specific API to reduce toplevel clutter
     */
    abstract val android: Android

    interface Android {
        /**
         * convenience method for [verifyKeyAttestation] specific to Android. Attests the public key contained in the leaf
         * @param attestationCerts attestation certificate chain
         * @param expectedChallenge attestation challenge
         */
        suspend fun verifyKeyAttestation(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ): KeyAttestation<PublicKey>

        /**
         * convenience method for [verifyKeyAttestation] specific to Android. Attests the public key contained in the leaf
         * @param attestationCerts attestation certificate chain
         * @param expectedChallenge attestation challenge
         */
        fun verifyKeyAttestationBlocking(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ): KeyAttestation<PublicKey> = runBlocking { verifyKeyAttestation(attestationCerts, expectedChallenge) }
    }
}

/**
 * Pairs an Apple [AppAttest](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
 * assertion with the referenced `clientData` value
 */
@JvmInline
value class AssertionData private constructor(private val pair: Pair<ByteArray, ByteArray>) {

    /**
     * Pairs an Apple AppAttest assertion with the referenced clientData value
     */
    constructor(assertion: ByteArray, clientData: ByteArray) : this(assertion to clientData)

    val assertion get() = pair.first
    val clientData get() = pair.second
}

/**
 * NOOP attestation service. Useful during unit tests for disabling attestation integrated into service endpoints.
 * Simply forwards inputs but performs no attestation whatsoever.
 *
 * Do not use in production!
 */

@DisabledAttestation
object NoopAttestationService : AttestationService() {

    @DisabledAttestation
    override suspend fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult =
        if (attestationProof.size > 2) AttestationResult.Android.NOOP(attestationProof)
        else AttestationResult.IOS.NOOP(clientData)

    @DisabledAttestation
    inline fun <T : PublicKey, R> KeyAttestation<T>.foldTyped(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult.NOOP) -> R
    ): R = if (isSuccess) onSuccess(attestedPublicKey!!, details as AttestationResult.NOOP)
    else onError(details as AttestationResult.Error)

    @DisabledAttestation
    override suspend fun doVerifyKeyAttestation(
        attestationProof: Attestation,
        challenge: ByteArray
    ): KeyAttestation<PublicKey> =
        when (attestationProof) {
            is IosHomebrewAttestation -> KeyAttestation(
                attestationProof.parsedClientData.publicKey.toJcaPublicKey().getOrThrow(),
                AttestationResult.IOS.NOOP(attestationProof.parsedClientData.publicKey.encodeToDer())
            )

            is AndroidKeystoreAttestation -> KeyAttestation(
                attestationProof.certificateChain.first().decodedPublicKey.getOrThrow().toJcaPublicKey().getOrThrow(),
                AttestationResult.Android.NOOP(attestationProof.certificateChain.map { it.encodeToDer() })
            )

            else -> KeyAttestation(
                attestedPublicKey = null,
                details = AttestationResult.Error(
                    explanation = "Unsupported attestation proof type",
                    cause = AttException.Content.Unknown(
                        message = null,
                        cause = IllegalArgumentException()
                    )
                )
            )
        }

    @DisabledAttestation
    override val ios: IOS
        get() = object : IOS {

            @DisabledAttestation
            override fun verifyAppAttestation(attestationObject: ByteArray, challenge: ByteArray) =
                runBlocking { verifyAttestation(listOf(attestationObject), challenge, clientData = null) }

            @DisabledAttestation
            override fun verifyCombined(
                attestationObject: ByteArray,
                assertionFromDevice: ByteArray,
                referenceClientData: ByteArray,
                challenge: ByteArray,
            ) = runBlocking {
                verifyAttestation(
                    listOf(attestationObject, assertionFromDevice),
                    challenge,
                    referenceClientData
                )
            }

            //Will always throw
            @DisabledAttestation
            override fun validateAssertionWithChallenge(
                validatedAttestation: ValidatedAttestation,
                assertion: ByteArray,
                expectedChallenge: ByteArray,
                lastSeenCounter: Long,
                maxCounter: Long
            ): Result<Assertion> = with(object : AssertionChallengeValidator {
                override fun validate(
                    assertionObj: Assertion,
                    clientData: ByteArray,
                    attestationPublicKey: ECPublicKey,
                    challenge: ByteArray
                ) = true
            }) {
                validateAssertion(
                    validatedAttestation,
                    assertion,
                    expectedChallenge,
                    expectedChallenge,
                    lastSeenCounter, maxCounter
                )
            }


            //Will always throw
            @DisabledAttestation
            context(validator: AssertionChallengeValidator)
            override fun validateAssertion(
                validatedAttestation: ValidatedAttestation,
                assertion: ByteArray,
                referenceClientData: ByteArray,
                expectedChallenge: ByteArray,
                lastSeenCounter: Long,
                maxCounterAdvance: Long
            ): Result<Assertion> {
                val envelope = assertionReader.readValue<AssertionEnvelope>(assertion)
                return catchingUnwrapped {
                    Assertion(envelope.signature, envelope.authenticatorDataParsed())
                }

            }

        }

    @DisabledAttestation
    override val android: Android
        get() = object : Android {
            @DisabledAttestation
            override suspend fun verifyKeyAttestation(
                attestationCerts: List<X509Certificate>,
                expectedChallenge: ByteArray
            ): KeyAttestation<PublicKey> = KeyAttestation(
                attestationCerts.first().publicKey, verifyAttestation(
                    attestationCerts.map { it.encoded },
                    expectedChallenge,
                )
            )
        }

}

@RequiresOptIn(message = "Access to disabled attestation. ALL BETS ARE OFF! NO AUTH GUARANTEES WHATSOEVER!")
/** This is dangerous. It is exposed if you know what you are doing. Never use in production, only for testing*/
annotation class DisabledAttestation()

