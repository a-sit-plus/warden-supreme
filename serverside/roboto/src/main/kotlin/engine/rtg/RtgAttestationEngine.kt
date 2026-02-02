package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.AttestationApplicationId
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import java.security.cert.X509Certificate
import java.time.YearMonth
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.jvm.optionals.getOrNull
import kotlin.time.Instant
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant

/**
 * Android attestation engine as reliable as a radioisotope thermoelectric generator (RTG).
 * Uses the legacy attestation parser from Google, patched for resilience
 */
sealed class RtgAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AndroidAttestationEngine<ParsedAttestationRecord, AuthorizationList, X509Certificate>(
    attestationConfiguration,
    verifyChallenge
) {

    override val certChainValidator = JvmCertChainValidator(attestationConfiguration)

    override val List<X509Certificate>.attestationRecord: ParsedAttestationRecord
        get() = ParsedAttestationRecord.createParsedAttestationRecord(this)
    override val ParsedAttestationRecord.challenge: ByteArray
        get() = this.attestationChallenge().toByteArray()

    override val ParsedAttestationRecord.createdAt: Instant?
        get() = (teeEnforced().creationDateTime().getOrNull() ?: softwareEnforced().creationDateTime()
            .getOrNull())?.toKotlinInstant()

    override val AuthorizationList.appIdForDiagnostics: AttestationApplicationId?
        get() = catchingUnwrapped { attestationApplicationId().get() }.getOrNull()

    @Throws(Throwable::class)
    override fun AuthorizationList.findMatchingPackageVersions(packageName: String): List<UInt> =
        attestationApplicationId().get().packageInfos().filter { it.packageName() == packageName }
            .map { it.version().toUInt() }

    @get:Throws(Throwable::class)
    override val AuthorizationList.signerFingerprints: Set<ByteArray>?
        get() = attestationApplicationId().get().signatureDigests().map { it.toByteArray() }.toSet()

    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyAndroidVersionFromAuthList(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Instant
    ) {
        catchingUnwrapped {
            (versionOverride ?: attestationConfiguration.androidVersion)?.let {
                if ((osVersion().get()) < it) throw AttestationValueException(
                    "Android version not supported: ${osVersion().get()} (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osVersion().get()
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                if ((osPatchLevel().get()).isBefore(YearMonth.of(it.year, it.month))) throw AttestationValueException(
                    "Patch level not supported: ${osPatchLevel().get()} (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osPatchLevel().get()
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                it.maxFuturePatchLevelMonths?.let { maxFuturePatchLevelMonths ->
                    val fromAttestation = osPatchLevel().get()
                    val calendar =
                        Calendar.getInstance(TimeZone.getTimeZone(ZoneOffset.UTC))
                            .apply { time = Date.from(verificationDate.toJavaInstant()) }
                    val currentYearMonth = YearMonth.of(calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH) + 1)
                    val difference = currentYearMonth.until(fromAttestation, ChronoUnit.MONTHS)
                    if (difference > maxFuturePatchLevelMonths.toLong()) throw AttestationValueException(
                        "Patch level is $difference months in the future. Maximum amount time travel allowed is: $maxFuturePatchLevelMonths months",
                        reason = AttestationValueException.Reason.OS_VERSION,
                        expectedValue = it,
                        actualValue = osPatchLevel().get()
                    )
                }
            }
        }.getOrElse {
            throw when (it) {
                is AttestationValueException -> it
                else -> AttestationValueException(
                    "Could not verify Android Version",
                    it,
                    AttestationValueException.Reason.OS_VERSION,
                    expectedValue = "Correct Android OS version",
                    actualValue = this
                )
            }
        }
    }

    override fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        if (rootOfTrust() == null) throw AttestationValueException(
            "Root of Trust not present",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = "Present Root of Trust",
            actualValue = null
        )

        if (!rootOfTrust().get().deviceLocked()) throw AttestationValueException(
            "Bootloader not locked",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = true,
            actualValue = false
        )

        if ((rootOfTrust().get().verifiedBootState()
                ?: RootOfTrust.VerifiedBootState.FAILED) != RootOfTrust.VerifiedBootState.VERIFIED
        ) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = RootOfTrust.VerifiedBootState.VERIFIED,
            actualValue = rootOfTrust().get().verifiedBootState()
        )
    }

    override val AuthorizationList.rollbackResistant: Boolean get() = rollbackResistance()

    override val ParsedAttestationRecord.attestationSecLevel: GeneralizedSecurityLevel
        get() = when (attestationSecurityLevel()) {
            ParsedAttestationRecord.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            ParsedAttestationRecord.SecurityLevel.STRONG_BOX -> GeneralizedSecurityLevel.STRONGBOX
        }

    override val ParsedAttestationRecord.keymasterSecLevel: GeneralizedSecurityLevel
        get() = when (keymasterSecurityLevel()) {
            ParsedAttestationRecord.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            ParsedAttestationRecord.SecurityLevel.STRONG_BOX -> GeneralizedSecurityLevel.STRONGBOX
        }


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