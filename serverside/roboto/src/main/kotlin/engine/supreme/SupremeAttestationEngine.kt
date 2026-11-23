package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList.RootOfTrust.VerifiedBootState
import at.asitplus.awesn1.toBigInteger
import at.asitplus.signum.indispensable.pki.CertificateChain
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.datetime.YearMonth
import kotlin.time.Instant

/**
 * Modern, better, independent KMP-first Attestation engine based on in-house clean-room
 * implementation of an attestation record parser that outperforms Google's legacy parser and Google's next-gen parser
 */
sealed class SupremeAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AndroidAttestationEngine<AttestationKeyDescription, AuthorizationList>(
    attestationConfiguration,
    verifyChallenge
) {
    override val certChainValidator = JvmCertChainValidator(attestationConfiguration)

    override val CertificateChain.attestationRecord: AttestationKeyDescription?
        get() = lastOrNull { it.hasAndroidKeyAttestationExtensionOid }?.androidAttestationExtension

    override fun CertificateChain.selectAttestedApplication() =
        selectAttestedApplication(attestationConfiguration.applications)

    override val AttestationKeyDescription.attestationSecLevel: SecurityLevel
        get() = attestationSecurityLevel

    override val AttestationKeyDescription.challenge: ByteArray
        get() = attestationChallenge

    override val AttestationKeyDescription.createdAt: Instant?
        get() = hardwareEnforced.creationDateTime?.getOrNull()?.timestamp
            ?: softwareEnforced.creationDateTime?.getOrNull()?.timestamp

    override val AttestationKeyDescription.keymasterSecLevel: SecurityLevel
        get() = keyMintSecurityLevel

    override val AuthorizationList.androidVersion: Result<BigInteger>?
        get() = osVersion?.toResult()?.map { it.intValue.toBigInteger() }

    override val AuthorizationList.appIdForDiagnostics: AttestationValue<AuthorizationList.AttestationApplicationId>?
        get() = attestationApplicationId

    @Throws(Throwable::class)
    override fun AuthorizationList.findMatchingPackageVersions(packageName: String): List<UInt> =
        attestationApplicationId?.getOrThrow()?.packageInfos?.filter {
            it.packageName == packageName
        }?.map { it.version } ?: emptyList()

    override val AuthorizationList.verifiedBootState: VerifiedBootState?
        get() = rootOfTrust?.getOrNull()?.verifiedBootState

    override val AuthorizationList.verifiedBootKeyDigest: ByteArray?
        get() = rootOfTrust?.getOrNull()?.verifiedBootKeyDigest

    override val AuthorizationList.hasRootOfTrust: Boolean get() = rootOfTrust?.getOrNull() != null

    override val AuthorizationList.isDeviceLocked: Boolean
        get() = rootOfTrust?.getOrNull()?.deviceLocked ?: false

    override val AuthorizationList.operatingSystemPatchLevel: YearMonth? get() = osPatchLevelLenient

    override val AuthorizationList.rollbackResistant: Boolean
        get() = (rollbackResistant?.getOrNull() ?: rollbackResistance?.getOrNull()) != null

    @get:Throws(Throwable::class)
    override val AuthorizationList.signerFingerprints: Set<ByteArray>?
        get() = attestationApplicationId?.getOrThrow()?.signatureDigests


    class Hardware(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean,
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        override val type by lazy { HardwareEngine() }

    }

    class Software(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        override val type by lazy { SoftwareEngine() }
    }

}
