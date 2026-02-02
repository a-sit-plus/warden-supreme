package  at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import io.ktor.util.*
import java.util.*
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.time.toJavaInstant


sealed class AndroidAttestationEngine<AttRecord, AuthList, Cert>(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    protected val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {
    abstract val certChainValidator: CertChainValidator<Cert>
    abstract val trustAnchors: Collection<TrustedRoot>

    abstract val List<Cert>.attestationRecord: AttRecord

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
        val parsedAttestationRecord = certificates.attestationRecord
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


    protected abstract fun AttRecord.verifyAttestationTime(verificationDate: Instant)

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData)

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
    protected abstract fun AuthList.verifyRollbackResistance()

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifySecurityLevel(appOverride: Boolean?)

}