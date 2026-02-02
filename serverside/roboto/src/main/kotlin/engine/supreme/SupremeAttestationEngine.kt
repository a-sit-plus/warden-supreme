package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.toBigInteger
import com.google.android.attestation.ParsedAttestationRecord
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.datetime.TimeZone
import kotlinx.datetime.YearMonth
import kotlinx.datetime.number
import kotlinx.datetime.toLocalDateTime
import java.security.cert.X509Certificate
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.time.toJavaInstant

/**
 * Modern, better, independent KMP-first Attestation engine based on in-house clean-room
 * implementation of an attestation record parser
 */
sealed class SupremeAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AndroidAttestationEngine<AttestationKeyDescription, AuthorizationList, X509Certificate>(
    attestationConfiguration,
    verifyChallenge
) {
    override val certChainValidator = JvmCertChainValidator(attestationConfiguration)

    override val List<X509Certificate>.attestationRecord: AttestationKeyDescription?
        get() = androidAttestationExtension
    override val AttestationKeyDescription.challenge: ByteArray
        get() = attestationChallenge

    override fun AttestationKeyDescription.verifyAttestationTime(verificationDate: Instant) {
        val checkTime = verificationDate + (attestationConfiguration.verificationSecondsOffset).seconds
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        //TODO: be more lenient here and accept month and day zero, but this should be configurable
        val createdAt = hardwareEnforced.creationDateTime?.getOrNull()?.timestamp
            ?: softwareEnforced.creationDateTime?.getOrNull()?.timestamp
        if (createdAt == null) throw AttestationValueException(
            "Attestation statement creation time missing",
            reason = AttestationValueException.Reason.STATEMENT_TIME,
            expectedValue = checkTime,
            actualValue = null
        )

        val difference = checkTime - createdAt
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

    override fun AttestationKeyDescription.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        //TODO extract raw ASN! value for failire instead of `getOrNull`
        catchingUnwrapped {
            val parsedValue = softwareEnforced.attestationApplicationId
            val matchingPackage = parsedValue?.getOrNull()?.packageInfos?.filter {
                it.packageName == application.packageName
            } ?: emptyList()
            if (matchingPackage.isEmpty()) {
                throw AttestationValueException(
                    "Invalid Application Package: $parsedValue (should be: ${application.packageName})",
                    reason = AttestationValueException.Reason.PACKAGE_NAME,
                    expectedValue = application.packageName,
                    actualValue = parsedValue
                )
            }
            application.appVersion?.let { configuredVersion ->
                if (matchingPackage.firstOrNull { it.version >= configuredVersion.toUInt() } == null) {
                    throw AttestationValueException(
                        "Application Version not supported",
                        reason = AttestationValueException.Reason.APP_VERSION,
                        expectedValue = configuredVersion,
                        actualValue = matchingPackage.map { it.version }
                    )
                }
            }

            if (parsedValue?.getOrNull()?.signatureDigests?.firstOrNull { fromAttestation ->
                    application.signerFingerprints.any { it.contentEquals(fromAttestation) }
                } == null) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signerFingerprints,
                    actualValue = parsedValue?.getOrNull()?.signatureDigests
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
                    actualValue = softwareEnforced
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
            val osVersionFromRecord = osVersion?.getOrNull()?.intValue?.toBigInteger()
            if ((osVersionFromRecord == null) || osVersionFromRecord < BigInteger(it)) throw AttestationValueException(
                "Android version not supported: $osVersionFromRecord} (should be at least $it)",
                reason = AttestationValueException.Reason.OS_VERSION,
                expectedValue = it,
                actualValue = osVersion
            )
        }

        (patchLevel ?: attestationConfiguration.patchLevel)?.let {
            val fromRecord = osPatchLevel?.getOrNull()?.let { YearMonth(it.year.toInt(), it.month) }
            if ((fromRecord == null) || (fromRecord < YearMonth(it.year, it.month))
            ) throw AttestationValueException(
                "Patch level not supported: ${fromRecord} (should be at least $it)",
                reason = AttestationValueException.Reason.OS_VERSION,
                expectedValue = it,
                actualValue = osPatchLevel
            )
        }

        (patchLevel ?: attestationConfiguration.patchLevel)?.let {
            it.maxFuturePatchLevelMonths?.let { maxFuturePatchLevelMonths ->
                val fromAttestation = osPatchLevel?.getOrNull()?.let { YearMonth(it.year.toInt(), it.month) }

                val currentYearMonth = verificationDate.toLocalDateTime(TimeZone.UTC).let { YearMonth(it.year, it.month) }
                if ((fromAttestation==null) || ( (monthsBetween(fromAttestation,currentYearMonth)) > maxFuturePatchLevelMonths)) throw AttestationValueException(
                    "Patch level is ${fromAttestation?.let { monthsBetween(it,currentYearMonth) }} months in the future. Maximum amount time travel allowed is: $maxFuturePatchLevelMonths months",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osPatchLevel
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

        val parsedRootOfTrust = rootOfTrust?.getOrNull()
        if (parsedRootOfTrust == null) throw AttestationValueException(
            "Root of Trust not present/valid",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = "Present Root of Trust",
            actualValue = rootOfTrust
        )

        if (!parsedRootOfTrust.deviceLocked) throw AttestationValueException(
            "Bootloader not locked",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = true,
            actualValue = false
        )

        if (parsedRootOfTrust.verifiedBootState  != AuthorizationList.RootOfTrust.VerifiedBootState.Verified
        ) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
            actualValue = parsedRootOfTrust.verifiedBootState
        )
    }

    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (rollbackResistant?.getOrNull()?:rollbackResistance?.getOrNull() ==null) throw AttestationValueException(
                "No rollback resistance",
                reason = AttestationValueException.Reason.ROLLBACK_RESISTANCE,
                expectedValue = true,
                actualValue = false
            )
    }

    class Hardware(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean,
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        init {
            if (attestationConfiguration.disableHardwareAttestation) throw object :
                AndroidAttestationException("Hardware attestation is disabled!", null) {}
            if (attestationConfiguration.hardwareTrustedRoots.isEmpty()) throw object :
                AndroidAttestationException("No hardware attestation trust anchors configured", null) {}
        }

        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.hardwareTrustedRoots


        @Throws(AttestationValueException::class)
        override fun AttestationKeyDescription.verifyAndroidVersion(
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) = hardwareEnforced.verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)

        @Throws(AttestationValueException::class)
        override fun AttestationKeyDescription.verifyBootStateAndSystemImage() = hardwareEnforced.verifySystemLocked()

        @Throws(AttestationValueException::class)
        override fun AttestationKeyDescription.verifyRollbackResistance() = hardwareEnforced.verifyRollbackResistance()


        @Throws(AttestationValueException::class)
        override fun AttestationKeyDescription.verifySecurityLevel(appOverride: Boolean?) {
            if (appOverride ?: attestationConfiguration.requireStrongBox) {
                if (attestationSecurityLevel != AttestationKeyDescription.SecurityLevel.STRONGBOX)
                    throw AttestationValueException(
                        "Attestation security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = attestationSecurityLevel
                    )
                if (keymasterSecurityLevel != AttestationKeyDescription.SecurityLevel.STRONGBOX)
                    throw AttestationValueException(
                        "Keymaster security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = keymasterSecurityLevel
                    )
            } else {
                if (attestationSecurityLevel == AttestationKeyDescription.SecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Attestation security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = attestationSecurityLevel
                    )
                if (keymasterSecurityLevel == AttestationKeyDescription.SecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Keymaster security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = keymasterSecurityLevel
                    )
            }

        }
    }

    class Software(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        init {
            if (!attestationConfiguration.enableSoftwareAttestation) throw object :
                AndroidAttestationException("Software attestation is disabled!", null) {}
            if (attestationConfiguration.softwareTrustedRoots.isEmpty()) throw object :
                AndroidAttestationException("No software attestation trust anchors configured", null) {}
        }

        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.softwareTrustedRoots

        override fun AttestationKeyDescription.verifyAndroidVersion(
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) =
            softwareEnforced.verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)

        override fun AttestationKeyDescription.verifyRollbackResistance() =
            softwareEnforced.verifyRollbackResistance()

        override fun AttestationKeyDescription.verifyBootStateAndSystemImage() {
            //impossible
        }

        @Throws(AttestationValueException::class)
        override fun AttestationKeyDescription.verifySecurityLevel(appOverride: Boolean? /*irrelevant*/) {
            if (attestationSecurityLevel != AttestationKeyDescription.SecurityLevel.SOFTWARE) throw AttestationValueException(
                "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = attestationSecurityLevel
            )
            if (keymasterSecurityLevel != AttestationKeyDescription.SecurityLevel.SOFTWARE) throw AttestationValueException(
                "Keymaster security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = keymasterSecurityLevel
            )
        }

    }

}


fun monthsBetween(start: YearMonth, end: YearMonth): Int =
    (end.year - start.year) * 12 + (end.month.number - start.month.number)
