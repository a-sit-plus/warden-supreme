package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.engine.AndroidAttestationEngine
import at.asitplus.attestation.android.engine.JvmCertChainValidator
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import java.security.cert.X509Certificate
import java.time.YearMonth
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.Calendar
import java.util.Date
import java.util.TimeZone
import kotlin.jvm.optionals.getOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
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

    override fun ParsedAttestationRecord.verifyAttestationTime(verificationDate: Instant) {
        val checkTime = verificationDate + (attestationConfiguration.verificationSecondsOffset).seconds
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        val createdAt =
            teeEnforced().creationDateTime().getOrNull() ?: softwareEnforced().creationDateTime().getOrNull()
        if (createdAt == null) throw AttestationValueException(
            "Attestation statement creation time missing",
            reason = AttestationValueException.Reason.STATEMENT_TIME,
            expectedValue = checkTime,
            actualValue = null
        )

        val difference = checkTime - createdAt.toKotlinInstant()
        if (difference < Duration.ZERO) throw AttestationValueException(
            "Attestation statement creation time too far in the future: $createdAt, check time: $checkTime",
            reason = AttestationValueException.Reason.STATEMENT_TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )

        if (difference > attestationConfiguration.attestationStatementValiditySeconds.seconds) throw AttestationValueException(
            "Attestation statement creation time too far in the past: $createdAt, check time: $checkTime, attestation statement validity in seconds: ${attestationConfiguration.attestationStatementValiditySeconds}",
            reason = AttestationValueException.Reason.STATEMENT_TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )
    }

    override fun ParsedAttestationRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        //TODO revamp this
        catchingUnwrapped {
            if (!(softwareEnforced().attestationApplicationId().get().packageInfos().any {
                    it.packageName() == application.packageName
                })
            ) {
                throw AttestationValueException(
                    "Invalid Application Package: ${
                        softwareEnforced().attestationApplicationId().get().packageInfos()
                            .joinToString { it.packageName() }
                    } (should be: ${application.packageName})",
                    reason = AttestationValueException.Reason.PACKAGE_NAME,
                    expectedValue = application.packageName,
                    actualValue = softwareEnforced().attestationApplicationId().get().packageInfos()
                        .joinToString { it.packageName() }
                )
            }
            application.appVersion?.let { configuredVersion ->
                if (softwareEnforced().attestationApplicationId().get().packageInfos().first()
                        .version() < configuredVersion
                ) {
                    throw AttestationValueException(
                        "Application Version not supported",
                        reason = AttestationValueException.Reason.APP_VERSION,
                        expectedValue = configuredVersion,
                        actualValue = softwareEnforced().attestationApplicationId().get().packageInfos().first()
                            .version()
                    )
                }
            }

            if (!softwareEnforced().attestationApplicationId().get().signatureDigests().any { fromAttestation ->
                    application.signerFingerprints.any { it.contentEquals(fromAttestation.toByteArray()) }
                }) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signerFingerprints,
                    actualValue = softwareEnforced().attestationApplicationId().get().signatureDigests()
                        .map { it.toByteArray() }
                )
            }
        }.onFailure {
            throw when (it) {
                is AttestationValueException -> it
                else -> AttestationValueException(
                    "Could not verify Client Application",
                    it,
                    reason = AttestationValueException.Reason.APP_UNEXPECTED,
                    expectedValue = "Correct app data",
                    actualValue = softwareEnforced()
                )
            }
        }
    }

    override fun AuthorizationList.verifyAndroidVersionFromAuthList(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Instant
    ) = catchingUnwrapped {
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

    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!rollbackResistance()) throw AttestationValueException(
                "No rollback resistance",
                reason = AttestationValueException.Reason.ROLLBACK_RESISTANCE,
                expectedValue = true,
                actualValue = false
            )
    }


    class Hardware(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean,
    ) : RtgAttestationEngine(attestationConfiguration, verifyChallenge) {
        init {
            if (attestationConfiguration.disableHardwareAttestation) throw object :
                AndroidAttestationException("Hardware attestation is disabled!", null) {}
            if (attestationConfiguration.hardwareTrustedRoots.isEmpty()) throw object :
                AndroidAttestationException("No hardware attestation trust anchors configured", null) {}
        }

        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.hardwareTrustedRoots


        @Throws(AttestationValueException::class)
        override fun ParsedAttestationRecord.verifyAndroidVersion(
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) = teeEnforced().verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)

        @Throws(AttestationValueException::class)
        override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() = teeEnforced().verifySystemLocked()

        @Throws(AttestationValueException::class)
        override fun ParsedAttestationRecord.verifyRollbackResistance() = teeEnforced().verifyRollbackResistance()


        @Throws(AttestationValueException::class)
        override fun ParsedAttestationRecord.verifySecurityLevel(appOverride: Boolean?) {
            if (appOverride ?: attestationConfiguration.requireStrongBox) {
                if (attestationSecurityLevel() != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                    throw AttestationValueException(
                        "Attestation security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = attestationSecurityLevel()
                    )
                if (keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                    throw AttestationValueException(
                        "Keymaster security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = keymasterSecurityLevel()
                    )
            } else {
                if (attestationSecurityLevel() == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Attestation security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = attestationSecurityLevel()
                    )
                if (keymasterSecurityLevel() == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Keymaster security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = keymasterSecurityLevel()
                    )
            }

        }
    }

    class Software(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
    ) : RtgAttestationEngine(attestationConfiguration, verifyChallenge) {
        init {
            if (!attestationConfiguration.enableSoftwareAttestation) throw object :
                AndroidAttestationException("Software attestation is disabled!", null) {}
            if (attestationConfiguration.softwareTrustedRoots.isEmpty()) throw object :
                AndroidAttestationException("No software attestation trust anchors configured", null) {}
        }

        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.softwareTrustedRoots

        override fun ParsedAttestationRecord.verifyAndroidVersion(
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) =
            softwareEnforced().verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)

        override fun ParsedAttestationRecord.verifyRollbackResistance() =
            softwareEnforced().verifyRollbackResistance()

        override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() {
            //impossible
        }

        @Throws(AttestationValueException::class)
        override fun ParsedAttestationRecord.verifySecurityLevel(appOverride: Boolean? /*irrelevant*/) {
            if (attestationSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE) throw AttestationValueException(
                "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = attestationSecurityLevel()
            )
            if (keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE) throw AttestationValueException(
                "Keymaster security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = keymasterSecurityLevel()
            )
        }

    }
}