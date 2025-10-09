package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.android.legacy.LegacyCertChainValidator
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.serialization.json.Json
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*

abstract class AttestationEngine<AttRecord, AuthList>(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    protected val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {

    protected open val certChainValidator: CertChainValidator =
        LegacyCertChainValidator(attestationConfiguration.httpProxy)

    protected abstract val trustAnchors: Collection<PublicKey>

    protected abstract fun AttRecord.verifyAttestationTime(verificationDate: Instant)

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData)

    @Throws(AttestationValueException::class)
    protected abstract fun AuthList.verifyAndroidVersion(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Date
    ): Unit?


    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifyBootStateAndSystemImage()

    @Throws(AttestationValueException::class)
    protected abstract fun AuthList.verifySystemLocked()

    @Throws(AttestationValueException::class)
    protected abstract fun AuthList.verifyRollbackResistance()

    /**
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    open fun collectDebugInfo(
        certificates: List<X509Certificate>,
        expectedChallenge: ByteArray,
        verificationDate: Date = Date(),
    ) = AndroidDebugAttestationStatement(
        this,
        attestationConfiguration,
        verificationDate,
        expectedChallenge,
        certificates
    )

    /**
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     * @return [ParsedAttestationRecord] on success
     * @throws AttestationValueException if a property fails to verify according to the current configuration
     * @throws RevocationException if a certificate has been revoked
     * @throws CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
    abstract fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): AttRecord

    @Throws(AttestationValueException::class)
    protected abstract fun AttRecord.verifySecurityLevel()

}

internal val json = Json { ignoreUnknownKeys = true }

