package at.asitplus.attestation.android

import at.asitplus.attestation.android.engine.AndroidAttestationEngine
import at.asitplus.attestation.android.engine.RtgAttestationEngine
import at.asitplus.attestation.android.engine.SupremeAttestationEngine
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.wardenVersion
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.coroutines.runBlocking
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.toKotlinInstant

/**
 * The object identifier containing the remote key provisioning extension.
 */
const val OID_RKP = "1.3.6.1.4.1.11129.2.1.30"


class Roboto
@JvmOverloads
constructor(
    val attestationConfiguration: AndroidAttestationConfiguration,
    private val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) {
    companion object Companion {

        /**
         * Version String of the current Warden Supreme release
         */
        val version: String = wardenVersion
    }

    internal suspend fun revocationListsFromLastCall() =
        engines.first().certChainValidator.revocationListsFromLastCall()


    private val engines = mutableListOf<AndroidAttestationEngine<*, *, X509Certificate>>().apply {
        if (!attestationConfiguration.disableHardwareAttestation) add(
            if (attestationConfiguration.experimentalParser)
                SupremeAttestationEngine.Hardware(
                    attestationConfiguration,
                    verifyChallenge
                )
            else RtgAttestationEngine.Hardware(
                attestationConfiguration,
                verifyChallenge
            )
        )
        if (attestationConfiguration.enableSoftwareAttestation) add(
            if (attestationConfiguration.experimentalParser)
                SupremeAttestationEngine.Software(
                    attestationConfiguration,
                    verifyChallenge
                )
            else RtgAttestationEngine.Software(
                attestationConfiguration,
                verifyChallenge
            )
        )
    }

    init {
        require(engines.isNotEmpty()) { "Attestation engine list is empty" }
    }

    /**
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    @JvmName("collectDebugInfo")
    fun collectDebugInfoBlocking(
        certificates: List<X509Certificate>,
        expectedChallenge: ByteArray,
        verificationDate: Date = Date(),
    ) = runBlocking { collectDebugInfo(certificates, expectedChallenge, verificationDate) }

    /**
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    @JvmName("collectDebugInfoSuspending")
    suspend fun collectDebugInfo(
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
    @JvmName("verifyAttestation")
    fun verifyAttestationBlocking(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): Any = runBlocking { verifyAttestation(certificates, verificationDate, expectedChallenge) }

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
    @JvmName("verifyAttestationSuspending")
    suspend fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): Any {
        val results = engines.map {
            catchingUnwrapped {
                it.verifyAttestation(
                    certificates,
                    verificationDate.toInstant().toKotlinInstant(),
                    expectedChallenge
                )
            }
        }
        return if (results.filter { it.isFailure }.size == engines.size) {
            //if time is off, then we need to treat is separately
            results.firstOrNull {
                (it.exceptionOrNull() is CertificateInvalidException &&
                        (it.exceptionOrNull() as CertificateInvalidException).reason == CertificateInvalidException.Reason.TIME)
                        || (it.exceptionOrNull() is RevocationException)
            }?.exceptionOrNull()?.let { throw it }

            throw results.last() //this way we are most lenient
                .exceptionOrNull()!!
        } else results.first { it.isSuccess }.getOrThrow()!!

    }

}