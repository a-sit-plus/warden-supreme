package at.asitplus.attestation.android.at.asitplus.attestation.android.legacy

import at.asitplus.attestation.android.AttestationEngine
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.android.signum.json
import at.asitplus.catchingUnwrapped
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.*
import java.time.Duration
import java.time.Instant
import java.time.YearMonth
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.jvm.optionals.getOrNull

/**
 * The OG WARDEN-roboto engine tied to the now-deprecated
 * [android-key-attestation](https://github.com/google/android-key-attestation) data model and parser,
 * backed by Google's current-gen [keyattestation](https://github.com/android/keyattestation) [CertPathValidator].
 * This engine is battle tested, having successfully processed millions of attestations in the field.
 */
abstract class LegacyAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AttestationEngine<ParsedAttestationRecord, AuthorizationList>(attestationConfiguration, verifyChallenge) {

    override fun ParsedAttestationRecord.verifyAttestationTime(verificationDate: Instant) {
        val checkTime = verificationDate.plusSeconds(attestationConfiguration.verificationSecondsOffset)
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        val createdAt =
            teeEnforced().creationDateTime().getOrNull() ?: softwareEnforced().creationDateTime().getOrNull()
        if (createdAt == null) throw AttestationValueException(
            "Attestation statement creation time missing",
            reason = AttestationValueException.Reason.TIME,
            expectedValue = checkTime,
            actualValue = null
        )

        val difference = Duration.between(createdAt, checkTime)
        if (difference.isNegative) throw AttestationValueException(
            "Attestation statement creation time too far in the future: $createdAt, check time: $checkTime",
            reason = AttestationValueException.Reason.TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )

        if (difference > Duration.ofSeconds(attestationConfiguration.attestationStatementValiditySeconds.toLong())) throw AttestationValueException(
            "Attestation statement creation time too far in the past: $createdAt, check time: $checkTime, attestation statement validity in seconds: ${attestationConfiguration.attestationStatementValiditySeconds}",
            reason = AttestationValueException.Reason.TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )


    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        //TODO revamp this
        catchingUnwrapped {
            if(softwareEnforced().attestationApplicationId() == null || softwareEnforced().attestationApplicationId().isEmpty()) // TODO should be checked in advance??
                throw AttestationValueException(
                    "softwareEnforced.attestationApplicationId == null",
                    reason = AttestationValueException.Reason.APP_UNEXPECTED, // TODO
                    expectedValue = "something",
                    actualValue = null,
                )

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
                    application.signatureDigests.any { it.contentEquals(fromAttestation.toByteArray()) }
                }) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signatureDigests,
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


    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyAndroidVersion(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Date
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
            val fromAttestation = osPatchLevel().get()

            if (fromAttestation.isBefore(YearMonth.of(it.year, it.month))) throw AttestationValueException(
                "Patch level not supported: ${osPatchLevel().get()} (should be at least $it)",
                reason = AttestationValueException.Reason.OS_VERSION,
                expectedValue = it,
                actualValue = osPatchLevel().get()
            )

            it.maxFuturePatchLevelMonths?.let { maxFuturePatchLevelMonths ->
                val calendar =
                    Calendar.getInstance(TimeZone.getTimeZone(ZoneOffset.UTC)).apply { time = verificationDate }
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


    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        if (rootOfTrust() == null || rootOfTrust().isEmpty) throw AttestationValueException( // TODO überall is empty check?!
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
    override fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date,
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord {
        val actualVerificationDate =
            Date.from(verificationDate.toInstant().plusSeconds(attestationConfiguration.verificationSecondsOffset))


        //do this before we check everything else to actually identify the app we're having here
        val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates) // GOOGLE
        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            catchingUnwrapped { parsedAttestationRecord.verifyApplication(app) }
        }.let {
            it.entries.firstOrNull { (_, result) -> result.isSuccess } ?: it.values.first().exceptionOrNull()!!
                .let { throw it }
        }.key

        val thisAppsTrustAnchors = attestedApp.trustAnchorOverrides ?: trustAnchors
        certChainValidator.verifyCertificateChain(
            certificates,
            actualVerificationDate,
            thisAppsTrustAnchors,
            ignoreLeafValidity = attestationConfiguration.ignoreLeafValidity,
        )

        val receivedChallenge = parsedAttestationRecord.attestationChallenge().toByteArray()
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
        parsedAttestationRecord.verifyAttestationTime(verificationDate.toInstant())
        parsedAttestationRecord.verifySecurityLevel()
        parsedAttestationRecord.verifyBootStateAndSystemImage()
        parsedAttestationRecord.verifyRollbackResistance()


        parsedAttestationRecord.verifyAndroidVersion(
            attestedApp.androidVersionOverride,
            attestedApp.patchLevelOverride,
            verificationDate
        )
        return parsedAttestationRecord
    }

    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifyAndroidVersion(
        versionOverride: Int? = null,
        osPatchLevel: PatchLevel?,
        verificationDate: Date
    ): Unit?

    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifyRollbackResistance()
}



class EternalX509Certificate(private val delegate: X509Certificate) : X509Certificate() {
    override fun toString() = delegate.toString()

    override fun getEncoded(): ByteArray = delegate.encoded

    override fun verify(key: PublicKey?) = delegate.verify(key)

    override fun verify(key: PublicKey?, sigProvider: String?) = delegate.verify(key, sigProvider)

    override fun getPublicKey(): PublicKey = delegate.publicKey

    override fun hasUnsupportedCriticalExtension(): Boolean = delegate.hasUnsupportedCriticalExtension()

    override fun getCriticalExtensionOIDs(): MutableSet<String> = delegate.criticalExtensionOIDs

    override fun getNonCriticalExtensionOIDs(): MutableSet<String> = delegate.nonCriticalExtensionOIDs

    override fun getExtensionValue(oid: String?): ByteArray = delegate.getExtensionValue(oid)

    override fun checkValidity() {
        /*NOOP*/
    }

    override fun checkValidity(date: Date?) {
        /*NOOP*/
    }

    override fun getVersion(): Int = delegate.version

    override fun getSerialNumber(): BigInteger = delegate.serialNumber

    override fun getIssuerDN(): Principal = delegate.issuerDN

    override fun getSubjectDN(): Principal = delegate.subjectDN

    override fun getNotBefore(): Date = delegate.notBefore

    override fun getNotAfter(): Date = delegate.notAfter

    override fun getTBSCertificate(): ByteArray = delegate.tbsCertificate

    override fun getSignature(): ByteArray = delegate.signature

    override fun getSigAlgName(): String = delegate.sigAlgName

    override fun getSigAlgOID(): String = delegate.sigAlgOID

    override fun getSigAlgParams(): ByteArray = delegate.sigAlgParams

    override fun getIssuerUniqueID(): BooleanArray = delegate.issuerUniqueID

    override fun getSubjectUniqueID(): BooleanArray = delegate.subjectUniqueID

    override fun getKeyUsage(): BooleanArray = delegate.keyUsage

    override fun getBasicConstraints(): Int = delegate.basicConstraints

}

internal val json = Json { ignoreUnknownKeys = true }

fun HttpClientConfig<*>.setup(proxyUrl: String?) =
    apply {
        install(HttpCache)
        install(ContentNegotiation) { json(json) }
        engine { proxyUrl?.let { proxy = ProxyBuilder.http(it) } }
    }
