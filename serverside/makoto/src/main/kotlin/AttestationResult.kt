package at.asitplus.attestation


import at.asitplus.attestation.AttestationException as AttException
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.ParsedAttestationRecord
import java.security.PublicKey
import java.security.cert.X509Certificate
import kotlin.jvm.optionals.getOrNull


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

    sealed interface Kind
    sealed interface Verified : Kind

    @DisabledAttestation
    sealed interface NOOP : Kind

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

        @DisabledAttestation
        class NOOP internal constructor(attestationCertificateChain: List<ByteArray>) :
            Android(attestationCertificateChain.mapNotNull { it.parseToCertificate() }), AttestationResult.NOOP {
            override val androidDetails = "NOOP"
            override val attestationRecord: ParsedAttestationRecord by lazy {
                ParsedAttestationRecord.createParsedAttestationRecord(
                    attestationCertificateChain.mapNotNull { it.parseToCertificate() }
                )
            }
        }

        class Verified(attestationCertificateChain: List<X509Certificate>) : Android(attestationCertificateChain),
            AttestationResult.Verified {

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
     * The [Makoto], returns [IOS.Verified], also setting [IOS.Verified.attestation].
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
            IOS(assertedClientData?.first), AttestationResult.Verified {
            override val iosDetails =
                "Verified(${attestation.certificate.publicKey.algorithm} public key: ${attestation.certificate.publicKey.encoded.encodeBase64()}, " +
                        "iOS version: (semVer=${iosVersion.first}, buildNumber=[${iosVersion.second}]), app: ${attestation.receipt.payload.appId}"
        }

        @DisabledAttestation
        class NOOP(clientData: ByteArray?) : IOS(clientData), AttestationResult.NOOP {
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


    }

    /**
     * Represents an attestation verification failure. Always contains an  [explanation] about what went wrong.
     */
    class Error(val explanation: String, val cause: AttException) : AttestationResult() {
        override val details = "Error($explanation, Cause: ${cause::class.qualifiedName}"
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
            result = 31 * result + (cause.hashCode() ?: 0)
            result = 31 * result + details.hashCode()
            return result
        }
    }
}

/**
 * Result type returned by [AttestationService.verifyKeyAttestation].
 * [attestedPublicKey] contains an attested public key if attestation was successful (null otherwise)
 * [details] contains the detailed attestation result (see [AttestationResult] for more details)
 *
 */
@ConsistentCopyVisibility
data class KeyAttestation<T : PublicKey> internal constructor(
    val attestedPublicKey: T?,
    val details: AttestationResult
) {
    val isSuccess get() = attestedPublicKey != null

    override fun toString() = "Key$details"

    @Suppress("UNUSED")
    inline fun <R> fold(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult.Verified?) -> R
    ): R = if (isSuccess) onSuccess(attestedPublicKey!!, details as? AttestationResult.Verified)
    else onError(details as AttestationResult.Error)


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