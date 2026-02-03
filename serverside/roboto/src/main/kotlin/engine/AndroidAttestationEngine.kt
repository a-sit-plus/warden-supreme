package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AttestationExtension
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.ConfigurationException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.ktor.util.*
import kotlinx.datetime.TimeZone
import kotlinx.datetime.YearMonth
import kotlinx.datetime.toLocalDateTime
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.time.toJavaInstant


sealed class AndroidAttestationEngine<AttRecord : AttestationExtension<AuthList>, AuthList : AttestationExtension.AuthList, Cert>(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    protected val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {
    abstract val certChainValidator: CertChainValidator<Cert>
    val trustAnchors: Collection<TrustedRoot> by lazy { type.trustAnchors }

    abstract val List<Cert>.attestationRecord: AttRecord?

    abstract val AttRecord.challenge: ByteArray

    /**
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     * @return [AttRecord] on success
     * @throws AttestationValueException if a property fails to verify according to the current configuration
     * @throws RevocationException if a certificate has been revoked
     * @throws CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
    suspend fun verifyAttestation(
        certificates: List<Cert>,
        verificationDate: Instant,
        expectedChallenge: ByteArray
    ): AttRecord {
        val actualVerificationDate =
            Date.from((verificationDate + attestationConfiguration.verificationSecondsOffset.seconds).toJavaInstant())


        //do this before we check everything else to actually identify the app we're having here
        val parsedAttestationRecord = catchingUnwrapped {
            certificates.attestationRecord ?: throw IllegalArgumentException("No attestation record present")
        }.getOrElse {
            throw AttestationValueException(
                "Could not parse attestation record",
                it,
                reason = AttestationValueException.Reason.APP_UNEXPECTED,
                expectedValue = "Parsable attestation record",
                actualValue = null
            )
        }
        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            catchingUnwrapped { parsedAttestationRecord.verifyApplication(app) }
        }.let {
            it.entries.firstOrNull { (_, result) -> result.isSuccess } ?: it.values.first().exceptionOrNull()!!
                .let { throw it }
        }.key

        val thisAppsTrustAnchors = attestedApp.trustedRootOverrides ?: trustAnchors
        val rkpRequired =
            attestedApp.requireRemoteKeyProvisioningOverride ?: attestationConfiguration.requireRemoteKeyProvisioning
        with(certChainValidator) {
            certificates.verifyCertificateChain(actualVerificationDate, thisAppsTrustAnchors, rkpRequired)
        }


        val receivedChallenge = parsedAttestationRecord.challenge
        if (!verifyChallenge(
                expectedChallenge,
                receivedChallenge
            )
        ) throw AttestationValueException(
            "verification of attestation challenge failed. Expected challenge: ${expectedChallenge.encodeBase64()}, received challenge: ${receivedChallenge.encodeBase64()}",
            reason = AttestationValueException.Reason.CHALLENGE,
            expectedValue = expectedChallenge,
            actualValue = receivedChallenge
        )
        parsedAttestationRecord.verifyAttestationTime(verificationDate)
        type.verifySecurityLevel(parsedAttestationRecord, attestedApp.requireStrongBoxOverride)

        type.verifyBootStateAndSystemImage(parsedAttestationRecord)
        type.verifyRollbackResistance(parsedAttestationRecord)


        type.verifyAndroidVersion(
            parsedAttestationRecord,
            attestedApp.androidVersionOverride,
            attestedApp.patchLevelOverride,
            verificationDate
        )
        return parsedAttestationRecord
    }


    protected fun AttRecord.verifyAttestationTime(verificationDate: Instant) {
        val checkTime = verificationDate + (attestationConfiguration.verificationSecondsOffset).seconds
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        val creationTime = createdAt ?: throw AttestationValueException(
            "Attestation statement creation time missing",
            reason = AttestationValueException.Reason.STATEMENT_TIME,
            expectedValue = checkTime,
            actualValue = null
        )

        val difference = checkTime - creationTime
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

    @Throws(AttestationValueException::class)
    protected fun AttRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        val appId = softwareEnforced.appIdForDiagnostics

        catchingUnwrapped {
            val matchingPackageVersions = softwareEnforced.findMatchingPackageVersions(application.packageName)

            if (matchingPackageVersions.isEmpty()) {
                throw AttestationValueException(
                    "Invalid Application Package: $matchingPackageVersions (should contain: ${application.packageName})",
                    reason = AttestationValueException.Reason.PACKAGE_NAME,
                    expectedValue = application.packageName,
                    actualValue = appId
                )
            }
            application.appVersion?.let { configuredVersion ->
                if (matchingPackageVersions.firstOrNull { it >= configuredVersion.toUInt() } == null) {
                    throw AttestationValueException(
                        "Application Version not supported",
                        reason = AttestationValueException.Reason.APP_VERSION,
                        expectedValue = configuredVersion,
                        actualValue = matchingPackageVersions
                    )
                }
            }
            val signatureDigests = softwareEnforced.signerFingerprints
            if (signatureDigests?.firstOrNull { fromAttestation ->
                    application.signerFingerprints.any { it.contentEquals(fromAttestation) }
                } == null) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signerFingerprints,
                    actualValue = signatureDigests
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
                    actualValue = appId
                )
            }
        }
    }

    protected abstract val AuthList.hasRootOfTrust: Boolean

    protected abstract val AuthList.isDeviceLocked: Boolean

    protected abstract val AuthList.generalizedVerifiedBootState: GeneralizedVerifiedBootState?

    @Throws(AttestationValueException::class)
    protected fun AuthList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        if (!hasRootOfTrust) throw AttestationValueException(
            "Root of Trust not present",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = "Present Root of Trust",
            actualValue = null
        )

        if (!isDeviceLocked) throw AttestationValueException(
            "Bootloader not locked",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = true,
            actualValue = false
        )

        if ((generalizedVerifiedBootState
                ?: GeneralizedVerifiedBootState.FAILED) != GeneralizedVerifiedBootState.VERIFIED
        ) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = RootOfTrust.VerifiedBootState.VERIFIED,
            actualValue = generalizedVerifiedBootState
        )
    }

    @Throws(AttestationValueException::class)
    protected fun AuthList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!rollbackResistant) throw AttestationValueException(
                "No rollback resistance",
                reason = AttestationValueException.Reason.ROLLBACK_RESISTANCE,
                expectedValue = true,
                actualValue = false
            )
    }

    protected abstract val AttRecord.createdAt: Instant?

    protected abstract val AuthList.appIdForDiagnostics: Any?

    @Throws(Throwable::class)
    protected abstract fun AuthList.findMatchingPackageVersions(packageName: String): List<UInt>

    @get:Throws(Throwable::class)
    protected abstract val AuthList.signerFingerprints: Set<ByteArray>?

    protected abstract val AuthList.rollbackResistant: Boolean

    protected abstract val AuthList.androidVersion: Result<BigInteger>?
    protected abstract val AuthList.operatingSystemPatchLevel: YearMonth?

    protected abstract val AttRecord.attestationSecLevel: GeneralizedSecurityLevel
    protected abstract val AttRecord.keymasterSecLevel: GeneralizedSecurityLevel

    @Throws(AttestationValueException::class)
    fun AuthList.verifyAndroidVersionFromAuthList(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Instant
    ) {
        catchingUnwrapped {
            (versionOverride ?: attestationConfiguration.androidVersion)?.let {
                val osVersionFromRecord = androidVersion
                if ((osVersionFromRecord == null)
                    || osVersionFromRecord.isFailure
                    || (osVersionFromRecord.getOrThrow() < BigInteger(it))
                ) throw AttestationValueException(
                    "Android version not supported: $osVersionFromRecord (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osVersionFromRecord
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                val fromRecord = operatingSystemPatchLevel

                if ((fromRecord == null) || (fromRecord < YearMonth(it.year, it.month))
                ) throw AttestationValueException(
                    "Patch level not supported: $fromRecord (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = fromRecord
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                it.maxFuturePatchLevelMonths?.let { maxFuturePatchLevelMonths ->
                    val fromRecord = operatingSystemPatchLevel
                    val currentYearMonth =
                        verificationDate.toLocalDateTime(TimeZone.UTC).let { YearMonth(it.year, it.month) }
                    val difference = fromRecord?.let { monthsBetween(currentYearMonth, it) }
                    if ((difference == null) || (difference > maxFuturePatchLevelMonths)
                    ) throw AttestationValueException(
                        "Patch level is $difference months in the future. Maximum amount time travel allowed is: $maxFuturePatchLevelMonths months",
                        reason = AttestationValueException.Reason.OS_VERSION,
                        expectedValue = it,
                        actualValue = fromRecord
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

    protected abstract val type: EngineType<AttRecord, AuthList>

    sealed interface EngineType<AttRecord : AttestationExtension<AuthList>, AuthList : AttestationExtension.AuthList> {
        @Throws(AttestationValueException::class)
        fun verifySecurityLevel(record: AttRecord, appOverride: Boolean?)
        val trustAnchors: Collection<TrustedRoot>

        @Throws(AttestationValueException::class)
        fun verifyAndroidVersion(
            record: AttRecord,
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        )

        @Throws(AttestationValueException::class)
        fun verifyRollbackResistance(record: AttRecord)

        @Throws(AttestationValueException::class)
        fun verifyBootStateAndSystemImage(record: AttRecord)
    }


    inner class SoftwareEngine : EngineType<AttRecord, AuthList> {

        init {
            if (!attestationConfiguration.enableSoftwareAttestation) throw ConfigurationException("Software attestation is disabled!")
            if (attestationConfiguration.softwareTrustedRoots.isEmpty()) throw ConfigurationException("No software attestation trust anchors configured")
        }


        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.softwareTrustedRoots

        @Throws(AttestationValueException::class)
        override fun verifySecurityLevel(record: AttRecord, appOverride: Boolean? /*irrelevant for SW*/) = record.run {
            if (attestationSecLevel != GeneralizedSecurityLevel.SOFTWARE) throw AttestationValueException(
                "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = attestationSecLevel
            )
            if (keymasterSecLevel != GeneralizedSecurityLevel.SOFTWARE) throw AttestationValueException(
                "Keymaster security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = keymasterSecLevel
            )
        }

        @Throws(AttestationValueException::class)
        override fun verifyAndroidVersion(
            record: AttRecord,
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) {
            record.run {
                softwareEnforced.verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)
            }
        }

        @Throws(AttestationValueException::class)
        override fun verifyRollbackResistance(record: AttRecord) {
            record.softwareEnforced.verifyRollbackResistance()
        }

        override fun verifyBootStateAndSystemImage(record: AttRecord) {
            /*NOOP in Software*/
        }
    }

    inner class HardwareEngine : EngineType<AttRecord, AuthList> {
        init {
            if (attestationConfiguration.disableHardwareAttestation) throw ConfigurationException("Hardware attestation is disabled!")
            if (attestationConfiguration.hardwareTrustedRoots.isEmpty()) throw ConfigurationException("No hardware attestation trust anchors configured")
        }


        override val trustAnchors: Collection<TrustedRoot> = attestationConfiguration.hardwareTrustedRoots

        @Throws(AttestationValueException::class)
        override fun verifyAndroidVersion(
            record: AttRecord,
            versionOverride: Int?,
            osPatchLevel: PatchLevel?,
            verificationDate: Instant
        ) {
            record.hardwareEnforced.verifyAndroidVersionFromAuthList(versionOverride, osPatchLevel, verificationDate)
        }

        @Throws(AttestationValueException::class)
        override fun verifyRollbackResistance(record: AttRecord) {
            record.hardwareEnforced.verifyRollbackResistance()
        }

        @Throws(AttestationValueException::class)
        override fun verifyBootStateAndSystemImage(record: AttRecord) {
            record.hardwareEnforced.verifySystemLocked()
        }

        @Throws(AttestationValueException::class)
        override fun verifySecurityLevel(record: AttRecord, appOverride: Boolean? /*irrelevant for SW*/) = record.run {
            if (appOverride ?: attestationConfiguration.requireStrongBox) {
                if (attestationSecLevel != GeneralizedSecurityLevel.STRONGBOX)
                    throw AttestationValueException(
                        "Attestation security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = attestationSecLevel
                    )
                if (keymasterSecLevel != GeneralizedSecurityLevel.STRONGBOX)
                    throw AttestationValueException(
                        "Keymaster security level not StrongBox",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                        actualValue = keymasterSecLevel
                    )
            } else {
                if (attestationSecLevel == GeneralizedSecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Attestation security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = attestationSecLevel
                    )
                if (keymasterSecLevel == GeneralizedSecurityLevel.SOFTWARE)
                    throw AttestationValueException(
                        "Keymaster security level software",
                        reason = AttestationValueException.Reason.SEC_LEVEL,
                        expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                        actualValue = keymasterSecLevel
                    )
            }
        }


    }

}


enum class GeneralizedSecurityLevel {
    SOFTWARE,
    TEE,
    STRONGBOX
}

enum class GeneralizedVerifiedBootState {
    VERIFIED,
    SELF_SIGNED,
    UNVERIFIED,
    FAILED
}