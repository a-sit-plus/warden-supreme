package  at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AttestationExtension
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.ParsedAttestationRecord
import io.ktor.util.*
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
    abstract val trustAnchors: Collection<TrustedRoot>

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
                expectedValue = "Prasable attestation record",
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
        parsedAttestationRecord.verifySecurityLevel(attestedApp.requireStrongBoxOverride)
        parsedAttestationRecord.verifyBootStateAndSystemImage()
        parsedAttestationRecord.verifyRollbackResistance()


        parsedAttestationRecord.verifyAndroidVersion(
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

    protected abstract fun AttRecord.verifyAndroidVersion(
        versionOverride: Int?,
        osPatchLevel: PatchLevel?,
        verificationDate: Instant
    ): Unit?

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifyRollbackResistance(): Unit?

    @Throws(AttestationValueException::class)
    protected abstract fun AuthList.verifyAndroidVersionFromAuthList(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Instant
    ): Unit?


    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifyBootStateAndSystemImage()

    @Throws(AttestationValueException::class)
    protected abstract fun AuthList.verifySystemLocked()

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

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifySecurityLevel(appOverride: Boolean?)

    protected abstract val AttRecord.createdAt: Instant?

    protected abstract val AuthList.appIdForDiagnostics: Any?

    @Throws(Throwable::class)
    protected abstract fun AuthList.findMatchingPackageVersions(packageName: String): List<UInt>

    @get:Throws(Throwable::class)
    protected abstract val AuthList.signerFingerprints: Set<ByteArray>?

    protected abstract val AuthList.rollbackResistant: Boolean

    protected abstract val AttRecord.attestationSecLevel: GeneralizedSecurityLevel
    protected abstract val AttRecord.keymasterSecLevel: GeneralizedSecurityLevel

    protected fun AttRecord.verifySecurityLevelIsHardware(appOverride: Boolean?) {
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

    protected fun AttRecord.verifySecurityLevelIsSoftware() {
        if (attestationSecLevel != GeneralizedSecurityLevel.SOFTWARE) throw AttestationValueException(
            "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
            expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
            actualValue =attestationSecLevel
        )
        if (keymasterSecLevel != GeneralizedSecurityLevel.SOFTWARE) throw AttestationValueException(
            "Keymaster security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
            expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
            actualValue = keymasterSecLevel
        )
    }
}


enum class GeneralizedSecurityLevel {
    SOFTWARE,
    TEE,
    STRONGBOX
}