package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import com.ionspin.kotlin.bignum.integer.BigInteger
import java.security.cert.X509Certificate
import kotlin.jvm.optionals.getOrNull
import kotlin.time.Instant
import kotlin.time.toKotlinInstant

/**
 * Android attestation engine as reliable as a radioisotope thermoelectric generator (RTG).
 * Uses the legacy attestation parser from Google, patched for resilience
 */
sealed class RtgAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AndroidAttestationEngine<ParsedAttestationRecord, AuthorizationList, X509Certificate, KeyAttestationCertPath>(
    attestationConfiguration,
    verifyChallenge
) {

    override val certChainValidator = JvmCertChainValidator(attestationConfiguration)

    override val List<X509Certificate>.attestationRecord: ParsedAttestationRecord
        get() = ParsedAttestationRecord.createParsedAttestationRecord(this)

    override fun List<X509Certificate>.selectAttestedApplication() =
        selectAttestedApplication(attestationConfiguration.applications)

    override val ParsedAttestationRecord.attestationSecLevel: GeneralizedSecurityLevel
        get() = when (attestationSecurityLevel()) {
            ParsedAttestationRecord.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            ParsedAttestationRecord.SecurityLevel.STRONG_BOX -> GeneralizedSecurityLevel.STRONGBOX
        }

    override val ParsedAttestationRecord.challenge: ByteArray
        get() = this.attestationChallenge().toByteArray()

    override val ParsedAttestationRecord.createdAt: Instant?
        get() = (teeEnforced().creationDateTime().getOrNull() ?: softwareEnforced().creationDateTime()
            .getOrNull())?.toKotlinInstant()

    override val ParsedAttestationRecord.keymasterSecLevel: GeneralizedSecurityLevel
        get() = when (keymasterSecurityLevel()) {
            ParsedAttestationRecord.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            ParsedAttestationRecord.SecurityLevel.STRONG_BOX -> GeneralizedSecurityLevel.STRONGBOX
        }

    override val AuthorizationList.androidVersion: Result<BigInteger>?
        get() = catchingUnwrapped { BigInteger(osVersion().get()) }

    override val AuthorizationList.appIdForDiagnostics: AttestationApplicationId?
        get() = catchingUnwrapped { attestationApplicationId().get() }.getOrNull()

    @Throws(Throwable::class)
    override fun AuthorizationList.findMatchingPackageVersions(packageName: String): List<UInt> =
        attestationApplicationId().get().packageInfos().filter { it.packageName() == packageName }
            .map { it.version().toUInt() }

    override val AuthorizationList.generalizedVerifiedBootState: GeneralizedVerifiedBootState?
        get() = when (catchingUnwrapped {  rootOfTrust().get()}.getOrNull()?.verifiedBootState()) {
            RootOfTrust.VerifiedBootState.VERIFIED -> GeneralizedVerifiedBootState.VERIFIED
            RootOfTrust.VerifiedBootState.SELF_SIGNED -> GeneralizedVerifiedBootState.SELF_SIGNED
            RootOfTrust.VerifiedBootState.UNVERIFIED -> GeneralizedVerifiedBootState.UNVERIFIED
            RootOfTrust.VerifiedBootState.FAILED -> GeneralizedVerifiedBootState.FAILED
            else -> null
        }

    override val AuthorizationList.verifiedBootKeyDigest: ByteArray?
        get() = catchingUnwrapped {  rootOfTrust()?.get()}.getOrNull()?.verifiedBootKey()?.toByteArray()

    override val AuthorizationList.hasRootOfTrust: Boolean get() = rootOfTrust() != null

    override val AuthorizationList.isDeviceLocked: Boolean
        get() = catchingUnwrapped {
            rootOfTrust().get().deviceLocked()
        }.getOrElse { false }

    override val AuthorizationList.operatingSystemPatchLevel: kotlinx.datetime.YearMonth?
        get() = catchingUnwrapped {
            osPatchLevel().get().let {
                kotlinx.datetime.YearMonth(it.year, it.monthValue)
            }
        }.getOrNull()

    override val AuthorizationList.rollbackResistant: Boolean get() = rollbackResistance()

    @get:Throws(Throwable::class)
    override val AuthorizationList.signerFingerprints: Set<ByteArray>?
        get() = attestationApplicationId().get().signatureDigests().map { it.toByteArray() }.toSet()


    class Hardware(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean,
    ) : RtgAttestationEngine(attestationConfiguration, verifyChallenge) {
        override val type by lazy { HardwareEngine() }

    }

    class Software(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
    ) : RtgAttestationEngine(attestationConfiguration, verifyChallenge) {

        override val type by lazy { SoftwareEngine() }
    }
}
