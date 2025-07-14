package at.asitplus.attestation

import at.asitplus.attestation.AttestationException.Certificate
import at.asitplus.attestation.AttestationException.Content
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import kotlinx.datetime.Clock
import java.security.PublicKey
import java.security.cert.CertPathValidatorException


/**
 * Indicated the platform an attestation check failed for.
 */
enum class Platform {
    IOS,
    ANDROID,

    /**
     * Indicates that the attestation data provided was utterly incomprehensible and no indication of platform is possible
     */
    UNKNOWN
}

/**
 * Provides additional details on why an attestation attempt failed, indicating which [platform] was being attested.
 * Although many reasons exist why an attestation may fail, all of them can be put into two categories:
 *  * [Content] e.g. version, app name, challenge, or key mismatch
 *  * [Certificate] e.g. chain rooted in an untrusted certificate, revocation, validity period
 *      * [Certificate.Trust] for trust issues
 *      * [Certificate.Time] for clock offset-related issues
 *
 *  More specific details about why the attestation failed are communicated to humans in [message] and are differentiated in [cause].
 *  A dedicated lazy property [platformSpecificCause] is present to evaluate and act upon such details (which is just an alias for [cause]).
 *  On Android, [platformSpecificCause] will always be an instance of [AndroidAttestationException] containing an
 *  [enumerable reason](https://a-sit-plus.github.io/android-attestation/-android%20%20-attestation%20-library/at.asitplus.attestation.android.exceptions/index.html)
 *  which will provide insights.
 *  <br>
 *  For iOS, less verbose details are communicated in [platformSpecificCause] due to a lack of a common root for all throwables.
 *
 *  Concrete examples of platform-specific error cases and their corresponding exceptions and reason codes, refer to [Content], [Certificate.Trust], and [Certificate.Time]
 *
 */
sealed class AttestationException(val platform: Platform, message: String? = null, cause: Throwable) :
    Throwable(message, cause) {

    /**
     * Alias for [cause] (with more accurate semantics)
     */
    val platformSpecificCause by lazy { cause }

    /**
     * Indicates that some value (key to be attests, bundle identifier or package name, team identified or signer certificate, etc.) failed to verify
     * This usually means that either the client's OS or the app was compromised/modified (or an implementation error occurred).
     * <br>
     * For Android, [platformSpecificCause] is always an [AttestationValueException], on iOS it is always an [IosAttestationException],
     * both of which have enumerable `reason` property, which is documented.
     *
     * ### Android Examples:
     * * Invalid package name: `platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.PACKAGE_NAME`
     * * Challenge mismatch: `platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.CHALLENGE`
     * * OS version too low: `platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.OS_VERSION`
     * * Public Key mismatch: `platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.APP_UNEXPECTED`
     * * System integrity: `platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.SYSTEM_INTEGRITY`
     * * A mismatch in security level can either result in the [platformSpecificCause] being [Content] and reason being [AttestationValueException.Reason.SEC_LEVEL]
     *   or a [Certificate.Trust] exception due to mismatching root certificates
     *
     * ### iOS Examples
     * * Invalid bundle identifier / team id / stage: `platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.IDENTIFIER`
     * * Challenge mismatch: `platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.CHALLENGE`
     * * OS version too low: `platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.OS_VERSION`
     * * Public Key mismatch: `platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.APP_UNEXPECTED`
     * * System integrity mismatch won't result in a valid attestation object obtained on the client, so this can never reach the back-end, except as a bogus attestation proof
     * that will fail the attestation check in various ways depending on how this fake proof was constructed.
     *
     *
     */
    open class Content private constructor(platform: Platform, message: String?, cause: Throwable) :
        AttestationException(platform, message = message, cause = cause) {
        companion object {
            fun Android(message: String? = null, cause: AttestationValueException) =
                Content(Platform.ANDROID, message, cause)

            fun iOS(message: String? = null, cause: IosAttestationException) = Content(Platform.IOS, message, cause)

            fun Unknown(message: String? = null, cause: Throwable) = Content(Platform.UNKNOWN, message, cause)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Content) return false
            if (!super.equals(other)) return false
            return true
        }

    }

    /**
     * Indicates a problem verifying the certificate chain the attestation statement is built upon.
     * This can either be just a borked certificate chain (i.e. just a wrong certificate somewhere in the chain),
     * or the chain not being rooted in a valid trust anchor.
     * Most probably, however, a legitimate app on a trusted OS will simply have fallen victim to the system clock
     * being too far ahead. This heavily depends on the OS a device was originally shipped with,
     * (or just Samsung being Samsung and being unable to correctly encode a timestamp conforming to ASN.1)
     */

    sealed class Certificate(platform: Platform, message: String?, cause: Throwable) :
        AttestationException(platform, message = message, cause = cause) {

        /**
         * Indicates that temporal certificate chain verification failed
         * (i.e. the client's clock is not synchronised with the back-end)
         */
        class Time private constructor(platform: Platform, message: String?, cause: Throwable) :
            Certificate(platform, message, cause) {
            companion object {
                fun Android(message: String? = null, cause: AndroidAttestationException) =
                    Time(Platform.ANDROID, message, cause)

                fun iOS(
                    message: String? = null,
                    cause: Throwable
                ) = Time(Platform.IOS, message, cause)

            }

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Time) return false
                if (!super.equals(other)) return false
                return true
            }

            override fun hashCode(): Int {
                return super.hashCode()
            }

        }

        /**
         * Indicates either a borked certificate chain or one that is not rooted in one of the configured trust anchors.
         * It can also indicate revoked certificates.
         */
        class Trust private constructor(platform: Platform, message: String?, cause: Throwable) :
            Certificate(platform, message, cause) {
            companion object {
                fun Android(message: String? = null, cause: AndroidAttestationException) =
                    Trust(Platform.ANDROID, message, cause)

                fun iOS(
                    message: String? = null,
                    cause: Throwable
                ) = Trust(Platform.IOS, message, cause)

            }

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Trust) return false
                if (!super.equals(other)) return false
                return true
            }

        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Certificate) return false
            if (!super.equals(other)) return false
            return true
        }

    }

    /**
     * Thrown on instantiation, for illegal configurations (e.g. no apps configured)
     */
    class Configuration(platform: Platform, message: String? = null, cause: Throwable) :
        AttestationException(platform, message = message, cause = cause) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Configuration) return false
            if (!super.equals(other)) return false
            return true
        }

    }

    override fun toString() =
        "AttestationException.${this::class.simpleName}: platform: $platform, message: ${message ?: cause?.message}, cause: $cause"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationException) return false

        if (platform != other.platform) return false
        if(platformSpecificCause is CertPathValidatorException && other.platformSpecificCause is CertPathValidatorException){
            val own = platformSpecificCause as CertPathValidatorException
            val other= other.platformSpecificCause as CertPathValidatorException
            if(own.reason != other.reason) return false
            if(own.certPath != other.certPath) return false
            if(own.index != other.index) return false
            return true
        }
        if (platformSpecificCause != other.platformSpecificCause) return false

        return true
    }

    override fun hashCode(): Int {
        var result = platform.hashCode()
        result = 31 * result + platformSpecificCause.hashCode()
        return result
    }
}


class IosAttestationException(msg: String? = null, cause: Throwable? = null, val reason: Reason) :
    Throwable(msg ?: cause?.message, cause) {
    enum class Reason {
        /**
         * Version number does not satisfy constraints (e.g. iOS version is too old)
         */
        OS_VERSION,

        /**
         * Attestation statement creation time in the future
         */
        STATEMENT_TIME,

        /**
         * Signature counter in the assertion is too high. This could mean either an implementation error on the client, or a compromised client app.
         */
        SIG_CTR,

        /**
         * Team ID and/or bundle ID and/or stage (development, production) mismatch
         */
        IDENTIFIER,

        /**
         * Happens if the challenge in the attestation record does not match the expected challenge
         */
        CHALLENGE,


        /**
         * Generic case, which must not happen for an authentic app. could be borked assertion data
         * (initial counter not zero, invalid attestation data, etc, KID mismatch).
         * In general, it is hard to tell whether app developers made a mistake or something fishy is going on
         */
        APP_UNEXPECTED,

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IosAttestationException) return false

        if (reason != other.reason) return false

        return true
    }

    override fun hashCode(): Int {
        return reason.hashCode()
    }
}

internal fun <T : PublicKey> logicalError(
    keyToBeAttested: T,
    attestationProof: List<ByteArray>,
    expectedChallenge: ByteArray
) = RuntimeException("Logical Error attesting key ${
    keyToBeAttested.encoded.encodeBase64()
} for attestation proof ${
    attestationProof.joinToString { it.encodeBase64() }
} with challenge ${expectedChallenge.encodeBase64()} at ${Clock.System.now()}")