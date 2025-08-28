@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.ParsedAttestationRecord
import org.slf4j.LoggerFactory
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*
import kotlin.jvm.optionals.getOrNull
import kotlin.time.ExperimentalTime
import at.asitplus.attestation.AttestationException as AttException

abstract class AttestationService {


    internal abstract fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray? = null
    ): AttestationResult


    abstract fun verifyKeyAttestation(attestationProof: Attestation, challenge: ByteArray): KeyAttestation<PublicKey>

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
        ReplaceWith("AttestationService.verifyAttestation(attestationProof, challenge)")
    )
    fun <T : PublicKey> verifyKeyAttestation(
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
                        if (it is AttException)
                            AttestationResult.Error(it.message ?: it.javaClass.simpleName, it)
                        else AttestationResult.Error(it.message ?: it.javaClass.simpleName)
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


    private fun <T : PublicKey> processAndroidAttestationResult(
        keyToBeAttested: T,
        firstTry: AttestationResult.Android
    ): KeyAttestation<T> =
        if (keyToBeAttested.toCryptoPublicKey() == firstTry.attestationCertificate.publicKey.toCryptoPublicKey()) {
            KeyAttestation(keyToBeAttested, firstTry)
        } else {
            val reason = "Android attestation failed: keyToBeAttested (${keyToBeAttested.toLogString()}) does not " +
                    "match key from attestation certificate: ${firstTry.attestationCertificate.publicKey.toLogString()}"
            AttException.Content.Android(
                reason, AttestationValueException(reason, null, AttestationValueException.Reason.APP_UNEXPECTED,
                    firstTry.attestationCertificate.publicKey.toLogString() as Any, keyToBeAttested.toLogString())
            ).toAttestationError(reason)
        }

    private fun <T : PublicKey> T.toLogString(): String? = encoded.encodeBase64()

    private fun <T : PublicKey> AttestationException.Content.toAttestationError(it: String): KeyAttestation<T> =
        KeyAttestation(null, AttestationResult.Error(it, this))


    /** Same as [verifyKeyAttestation], but taking an encoded (either ANSI X9.63 or DER) publix key as a byte array
     * @see verifyKeyAttestation
     */
    fun verifyKeyAttestation(
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
         * First, it verifies the app attestation, afterwards it verifies the assertion, checks whether at most [counter] many signatures
         * have been performed using the key bound to the attestation before signing the assertion and verifies whether the client data
         * referenced within the assertion matches [referenceClientData]
         *
         * @param attestationObject the AppAttest attestation object to verify
         * @param assertionFromDevice the assertion data created on the device.
         * @param referenceClientData the expected client data to be contained in [assertionFromDevice]
         * @param counter the highest expected value of the signature counter prior to creating the assertion.
         */
        fun verifyAssertion(
            attestationObject: ByteArray,
            assertionFromDevice: ByteArray,
            referenceClientData: ByteArray,
            challenge: ByteArray,
            counter: Long = 0
        ): AttestationResult
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
        fun verifyKeyAttestation(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ): KeyAttestation<PublicKey>
    }
}

/**
 * Pairs an Apple [AppAttest](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
 * assertion with the referenced `clientData` value
 */
@JvmInline
value class AssertionData private constructor(private val pair: Pair<ByteArray, ByteArray>) {

    /**
     * Pairs an Apple AppAttest  assertion with the referenced clientData value
     */
    constructor(assertion: ByteArray, clientData: ByteArray) : this(assertion to clientData)

    val assertion get() = pair.first
    val clientData get() = pair.second
}

/**
 * Attestation result class. Successful results contain attested data. Typically contained within a
 * [KeyAttestation] object.
 */
sealed class AttestationResult {

    override fun toString() = "AttestationResult::$details)"
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationResult) return false

        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        return details.hashCode()
    }

    protected abstract val details: String

    /**
     * Successful Android Key Attestation result. [attestationCertificateChain] contains the attested certificate.
     *
     * All attested information in [attestationRecord] is available for further processing, should this be desired.
     * Note: this will fail when using the [NoopAttestationService]!
     */
    @Suppress("MemberVisibilityCanBePrivate")
    abstract class Android(val attestationCertificateChain: List<X509Certificate>) :
        AttestationResult() {

        protected abstract val androidDetails: String
        override val details: String by lazy { "Android::$androidDetails" }
        abstract val attestationRecord: ParsedAttestationRecord

        val attestationCertificate by lazy { attestationCertificateChain.first() }

        internal class NOOP internal constructor(attestationCertificateChain: List<ByteArray>) :
            Android(attestationCertificateChain.mapNotNull { it.parseToCertificate() }) {
            override val androidDetails = "NOOP"
            override val attestationRecord: ParsedAttestationRecord by lazy {
                ParsedAttestationRecord.createParsedAttestationRecord(
                    attestationCertificateChain.mapNotNull { it.parseToCertificate() }
                )
            }
        }

        class Verified(attestationCertificateChain: List<X509Certificate>) : Android(attestationCertificateChain) {

            override val attestationRecord: ParsedAttestationRecord =
                ParsedAttestationRecord.createParsedAttestationRecord(
                    attestationCertificateChain
                )
            override val androidDetails =
                "Verified(keyMaster security level: ${attestationRecord.keymasterSecurityLevel().name}, " +
                        "attestation security level: ${attestationRecord.attestationSecurityLevel().name}, " +
                        "${attestationRecord.attestedKey().algorithm} public key: ${attestationRecord.attestedKey().encoded.encodeBase64()}" + attestationRecord.softwareEnforced()
                    .attestationApplicationId()
                    .getOrNull()
                    ?.let { app ->
                        ", packageInfos: ${
                            app.packageInfos().joinToString(
                                prefix = "[",
                                postfix = "]"
                            ) { info: AttestationApplicationId.AttestationPackageInfo -> "${info.packageName()}:${info.version()}" }
                        }"
                    }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Android) return false

            if (attestationCertificateChain.map { it.encoded.encodeBase64() } != other.attestationCertificateChain.map { it.encoded.encodeBase64() }) return false
            if (androidDetails != other.androidDetails) return false

            return true
        }

        override fun hashCode(): Int {
            var result = attestationCertificateChain.map { it.encoded.contentHashCode() }.hashCode()
            result = 31 * result + androidDetails.hashCode()
            return result
        }
    }


    /**
     * Successful iOS attestation. If [AttestationService.verifyKeyAttestation] returned this, [clientData] contains the
     * encoded attested public key.
     * The [Warden], returns [IOS.Verified], also setting [IOS.Verified.attestation].
     * The [NoopAttestationService] returns [IOS.NOOP] (which is useful to as it enables skipping any
     * and all attestation checks for unit testing, when used with dependency injection, for example).
     */
    @Suppress("MemberVisibilityCanBePrivate")
    abstract class IOS(val clientData: ByteArray?) : AttestationResult() {

        abstract val iosDetails: String
        override val details: String by lazy { "iOS::$iosDetails" }

        class Verified(
            val attestation: ValidatedAttestation,
            val iosVersion: ParsedVersions,
            val assertedClientData: Pair<ByteArray, Assertion>?
        ) :
            IOS(assertedClientData?.first) {
            override val iosDetails =
                "Verified(${attestation.certificate.publicKey.algorithm} public key: ${attestation.certificate.publicKey.encoded.encodeBase64()}, " +
                        "iOS version: (semVer=${iosVersion.first}, buildNumber=[${iosVersion.second}]), app: ${attestation.receipt.payload.appId}"
        }

        class NOOP(clientData: ByteArray?) : IOS(clientData) {
            override val iosDetails = "NOOP"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is IOS) return false

            if (clientData != null) {
                if (other.clientData == null) return false
                if (!clientData.contentEquals(other.clientData)) return false
            } else if (other.clientData != null) return false
            if (iosDetails != other.iosDetails) return false

            return true
        }

        override fun hashCode(): Int {
            var result = clientData?.contentHashCode() ?: 0
            result = 31 * result + iosDetails.hashCode()
            return result
        }

        /**
         * Represents an attestation verification failure. Always contains an  [explanation] about what went wrong.
         */
    }

    class Error(val explanation: String, val cause: AttException? = null) : AttestationResult() {
        override val details = "Error($explanation" + cause?.let { ", Cause: ${cause::class.qualifiedName}" }
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Error) return false

            if (explanation != other.explanation) return false
            if (cause != other.cause) return false
            if (details != other.details) return false

            return true
        }

        override fun hashCode(): Int {
            var result = explanation.hashCode()
            result = 31 * result + (cause?.hashCode() ?: 0)
            result = 31 * result + details.hashCode()
            return result
        }
    }
}

/**
 * Result type returned by [AttestationService.verifyKeyAttestation].
 * [attestedPublicKey] contains attested public key if attestation was successful (null otherwise)
 * [details] contains the detailed attestation result (see [AttestationResult] for more details)
 *
 */
data class KeyAttestation<T : PublicKey> internal constructor(
    val attestedPublicKey: T?,
    val details: AttestationResult
) {
    val isSuccess get() = attestedPublicKey != null

    override fun toString() = "Key$details"

    @Suppress("UNUSED")
    inline fun <R> fold(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult) -> R
    ): R =
        if (isSuccess) onSuccess(attestedPublicKey!!, details)
        else {
            onError(details as AttestationResult.Error)
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyAttestation<*>) return false

        if (!attestedPublicKey?.encoded.contentEquals(other.attestedPublicKey?.encoded)) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestedPublicKey?.encoded?.contentHashCode() ?: 0
        result = 31 * result + details.hashCode()
        return result
    }


}

/**
 * NOOP attestation service. Useful during unit tests for disabling attestation integrated into service endpoints.
 * Simply forwards inputs but performs no attestation whatsoever.
 *
 * Do not use in production!
 */

object NoopAttestationService : AttestationService() {

    private val log = LoggerFactory.getLogger(this.javaClass)
    override fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult =
        if (attestationProof.size > 2) AttestationResult.Android.NOOP(attestationProof)
        else AttestationResult.IOS.NOOP(clientData)

    override fun verifyKeyAttestation(attestationProof: Attestation, challenge: ByteArray): KeyAttestation<PublicKey> =
        when (attestationProof) {
            is IosHomebrewAttestation -> KeyAttestation(
                attestationProof.parsedClientData.publicKey.toJcaPublicKey().getOrThrow(),
                AttestationResult.IOS.NOOP(attestationProof.parsedClientData.publicKey.encodeToDer())
            )

            is AndroidKeystoreAttestation -> KeyAttestation(
                attestationProof.certificateChain.first().decodedPublicKey.getOrThrow().toJcaPublicKey().getOrThrow(),
                AttestationResult.Android.NOOP(attestationProof.certificateChain.map { it.encodeToDer() })
            )

            else -> KeyAttestation(null, AttestationResult.Error("Unsupported attestation proof type"))
        }

    override val ios: IOS
        get() = object : IOS {
            override fun verifyAppAttestation(attestationObject: ByteArray, challenge: ByteArray) =
                verifyAttestation(listOf(attestationObject), challenge, clientData = null)

            override fun verifyAssertion(
                attestationObject: ByteArray,
                assertionFromDevice: ByteArray,
                referenceClientData: ByteArray,
                challenge: ByteArray,
                counter: Long
            ) = verifyAttestation(listOf(attestationObject, assertionFromDevice), challenge, referenceClientData)

        }
    override val android: Android
        get() = TODO("Not yet implemented")
}

