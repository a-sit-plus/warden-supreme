package at.asitplus.attestation.android

import at.asitplus.KmmResult
import at.asitplus.attestation.android.engine.AndroidAttestationEngine
import at.asitplus.attestation.android.engine.RtgAttestationEngine
import at.asitplus.attestation.android.engine.SupremeAttestationEngine
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.ConfigurationException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.wardenVersion
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.coroutines.runBlocking
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Clock
import kotlin.time.Instant
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

    //this works because all share the same config -> same revocation lists
    internal suspend fun revocationListsFromLastCall() =
        engines.first().certChainValidator.revocationListsFromLastCall()


    private val engines = mutableListOf<AndroidAttestationEngine<*, *, X509Certificate>>().apply {
        if (!attestationConfiguration.disableHardwareAttestation) add(
            if (attestationConfiguration.supremeParser)
                SupremeAttestationEngine.Hardware(attestationConfiguration, verifyChallenge)
            else RtgAttestationEngine.Hardware(attestationConfiguration, verifyChallenge)
        )
        if (attestationConfiguration.enableSoftwareAttestation) add(
            if (attestationConfiguration.supremeParser)
                SupremeAttestationEngine.Software(attestationConfiguration, verifyChallenge)
            else RtgAttestationEngine.Software(attestationConfiguration, verifyChallenge)
        )
    }

    init {
        if (engines.isEmpty()) throw ConfigurationException("Neither hardware nor software attestation enabled")
        // Fail fast on misconfiguration (e.g., missing trust anchors) instead of deferring to first verification call.
        engines.forEach { it.trustAnchors }
    }


    /**
     * **Java-Friendly method**
     *
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    @JvmName("collectDebugInfo")
    fun collectDebugInfoJ(
        certificates: List<X509Certificate>,
        expectedChallenge: ByteArray,
        verificationDate: Date = Date(),
    ) = collectDebugInfoBlocking(certificates, expectedChallenge, verificationDate.toInstant().toKotlinInstant())

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
        verificationDate: Instant = Clock.System.now(),
    ) = AndroidDebugAttestationStatement(
        this,
        attestationConfiguration,
        verificationDate,
        expectedChallenge,
        certificates
    )

    /**
     * **Java-Friendly method**
     *
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     * @return [AttestationExtension] on success
     * @throws AttestationValueException if a property fails to verify according to the current configuration
     * @throws RevocationException if a certificate has been revoked
     * @throws CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
    @JvmName("verifyAttestation")
    @Deprecated("To be removed in 1.1", replaceWith = ReplaceWith("verify(certificates, verificationDate, expectedChallenge).getOrThrow().attestationExension"))
    fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord =
        verifyBlocking(
            certificates,
            verificationDate.toInstant().toKotlinInstant(),
            expectedChallenge
        ).getOrThrow().parsedAttestationRecord ?: throw AttestationValueException(
            "Could not parse attestation record",
            reason = AttestationValueException.Reason.APP_UNEXPECTED,
            expectedValue = "A parseabel attestation record",
            actualValue = null
        )

    /**
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     *
     * @return `KmmResult<List<X509Certificate>>`. Failures contain a subclass of [AndroidAttestationException]:
     * * AttestationValueException if a property fails to verify according to the current configuration
     * * RevocationException if a certificate has been revoked
     * * CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
    suspend fun verify(
        certificates: List<X509Certificate>,
        verificationDate: Instant = Clock.System.now(),
        expectedChallenge: ByteArray
        //todo full chain inside a result and replaceWith to chain.parsedAttestationRecord or chain.AttestationKeyExn
    ): KmmResult<List<X509Certificate>> = catching {
        val results = engines.map {
            catchingUnwrapped {
                it.verifyAttestation(
                    certificates,
                    verificationDate,
                    expectedChallenge
                )
            }
        }
        if (results.filter { it.isFailure }.size == engines.size) {
            //if time is off, then we need to treat is separately
            results.firstOrNull {
                (it.exceptionOrNull() is CertificateInvalidException &&
                        (it.exceptionOrNull() as CertificateInvalidException).reason == CertificateInvalidException.Reason.TIME)
                        || (it.exceptionOrNull() is RevocationException)
            }?.exceptionOrNull()?.let { throw it }

            throw results.last() //this way we are most lenient
                .exceptionOrNull()!!
        } else certificates

    }
}

/**
 * Blocking version of [Roboto.verifyAttestation]
 */
@Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
fun Roboto.verifyBlocking(
    certificates: List<X509Certificate>,
    verificationDate: Instant = Clock.System.now(),
    expectedChallenge: ByteArray
): KmmResult<List<X509Certificate>> = runBlocking { verify(certificates, verificationDate, expectedChallenge) }

/**
 * Blocking version of [Roboto.collectDebugInfo]
 */
fun Roboto.collectDebugInfoBlocking(
    certificates: List<X509Certificate>,
    expectedChallenge: ByteArray,
    verificationDate: Instant = Clock.System.now(),
) = runBlocking { collectDebugInfo(certificates, expectedChallenge, verificationDate) }

/**
 * Convenience helper to get a legacy [ParsedAttestationRecord] from a certificate chain.
 * Returns `null` if no record is present or parsing is impossible
 */
@Deprecated("Will be removed soon", replaceWith = ReplaceWith("attestationExtension"))
val List<X509Certificate>.parsedAttestationRecord: ParsedAttestationRecord?
    get() = catching {
        ParsedAttestationRecord.createParsedAttestationRecord(
            this
        )
    }.getOrNull()