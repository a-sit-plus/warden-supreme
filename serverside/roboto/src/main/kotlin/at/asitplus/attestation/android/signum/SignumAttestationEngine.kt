package at.asitplus.attestation.android.signum

import at.asitplus.attestation.android.AttestationEngine
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.attestation.AttestationKeyDescription
import at.asitplus.signum.indispensable.pki.attestation.AuthorizationList
import at.asitplus.signum.indispensable.pki.attestation.androidAttestationExtension
import at.asitplus.signum.indispensable.toKmpCertificate
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.datetime.toJavaMonth
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
import kotlin.time.ExperimentalTime
import kotlin.time.toJavaInstant

/**

 */
abstract class SignumAttestationEngine(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) : AttestationEngine<AttestationKeyDescription, AuthorizationList>(attestationConfiguration, verifyChallenge) {

    @OptIn(ExperimentalTime::class) // TODO ?
    override fun AttestationKeyDescription.verifyAttestationTime(verificationDate: Instant) {
        val checkTime = verificationDate.plusSeconds(attestationConfiguration.verificationSecondsOffset)
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        val createdAt =
            (hardwareEnforced.creationDateTime ?: softwareEnforced.creationDateTime) ?.onSuccess { it.timestamp }
            ?: throw AttestationValueException(
                "Attestation statement creation time missing",
                reason = AttestationValueException.Reason.TIME,
                expectedValue = checkTime,
                actualValue = null
            )

        val difference = Duration.between(createdAt.toJavaInstant(), checkTime)

        if (difference.isNegative) throw AttestationValueException(
            "Attestation statement creation time too far in the future: $createdAt, check time: $checkTime",
            reason = AttestationValueException.Reason.TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )

        if (difference > Duration.ofSeconds(attestationConfiguration.attestationStatementValiditySeconds)) throw AttestationValueException(
            "Attestation statement creation time too far in the past: $createdAt, check time: $checkTime, attestation statement validity in seconds: ${attestationConfiguration.attestationStatementValiditySeconds}",
            reason = AttestationValueException.Reason.TIME,
            expectedValue = checkTime,
            actualValue = createdAt
        )


    }

    @Throws(AttestationValueException::class)
    override fun AttestationKeyDescription.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        //TODO revamp this
        catchingUnwrapped {
            if(softwareEnforced.attestationApplicationId == null) // TODO
                throw AttestationValueException(
                    "softwareEnforced.attestationApplicationId == null",
                    reason = AttestationValueException.Reason.APP_UNEXPECTED, // TODO
                    expectedValue = "something",
                    actualValue = null,
                )

            /*
            softwareEnforced.attestationApplicationId?.onSuccess {
                it.packageInfos.any { it.packageName == application.packageName }
            }
            */

            if(!softwareEnforced.attestationApplicationId!!.get().packageInfos.any {
                    it.packageName == application.packageName
                })
            {
                throw AttestationValueException(
                    "Invalid Application Package: ${
                        softwareEnforced.attestationApplicationId?.onSuccess { it.packageInfos.joinToString { it.packageName }}
                    } (should be: ${application.packageName})",
                    reason = AttestationValueException.Reason.PACKAGE_NAME,
                    expectedValue = application.packageName,
                    actualValue = softwareEnforced.attestationApplicationId?.onSuccess { it.packageInfos.joinToString { it.packageName }}
                )
            }
            application.appVersion?.let { configuredVersion ->
                if (softwareEnforced.attestationApplicationId!!.get().packageInfos.first()
                        .version.toInt() < configuredVersion // TODO appData.appVersion is Int but AttestationPackageInfo.version is UInt => make uniform?
                ) {
                    throw AttestationValueException(
                        "Application Version not supported",
                        reason = AttestationValueException.Reason.APP_VERSION,
                        expectedValue = configuredVersion,
                        actualValue = softwareEnforced.attestationApplicationId!!.get().packageInfos.first().version
                    )
                }
            }
            softwareEnforced.attestationApplicationId?.onSuccess { it.signatureDigests.any { fromAttestation ->
                    application.signatureDigests.any { it.contentEquals(fromAttestation) }
                }}
                ?:
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signatureDigests,
                    actualValue = softwareEnforced.attestationApplicationId?.onSuccess { it.signatureDigests }
                )
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


    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyAndroidVersion(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Date
    ) = catchingUnwrapped {
        (versionOverride ?: attestationConfiguration.androidVersion)?.let {
            if ((osVersion!!.get().intValue.toBigInteger()) < com.ionspin.kotlin.bignum.integer.BigInteger(it)) // TODO java.BigInteger is used in interface
                throw AttestationValueException(
                    "Android version not supported: ${osVersion} (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osVersion
                )
        }

        (patchLevel ?: attestationConfiguration.patchLevel)?.let {
            val fromAttestation = osPatchLevel!!.get().let{ YearMonth.of(it.year.toInt(),it.month.toJavaMonth()) } // TODO check if correct? create as member of OsPatchLevel, or derive from "Asn1YearMonth"?

            if (fromAttestation.isBefore(YearMonth.of(it.year, it.month))) throw AttestationValueException(
                "Patch level not supported: ${osPatchLevel} (should be at least $it)",
                reason = AttestationValueException.Reason.OS_VERSION,
                expectedValue = it,
                actualValue = osPatchLevel
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


    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        if (rootOfTrust == null) throw AttestationValueException(
            "Root of Trust not present",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = "Present Root of Trust",
            actualValue = null
        )

        //if (!rootOfTrust?.onSuccess { it.deviceLocked }) throw AttestationValueException(
        if (!rootOfTrust!!.get().deviceLocked) throw AttestationValueException(
            "Bootloader not locked",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = true,
            actualValue = false
        )

        val verifiedBootState = rootOfTrust?.onSuccess { it.verifiedBootState }
            ?: RootOfTrust.VerifiedBootState.FAILED

        if (verifiedBootState != RootOfTrust.VerifiedBootState.VERIFIED) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = RootOfTrust.VerifiedBootState.VERIFIED,
            actualValue = verifiedBootState
        )
    }

    @Throws(AttestationValueException::class)
    override fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (rollbackResistance == null || !rollbackResistance!!.isSuccess()) // TODO not sure if this is correct way to handle Tags?
                throw AttestationValueException(
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
    ): AttestationKeyDescription {
        val sCertificates = certificates.map { it.toKmpCertificate().getOrThrow() } // name shadowing
        val actualVerificationDate =
            Date.from(verificationDate.toInstant().plusSeconds(attestationConfiguration.verificationSecondsOffset))

        //do this before we check everything else to actually identify the app we're having here
        // TODO REMOVE OLD
        //val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates) // GOOGLE
        val keyDescription : AttestationKeyDescription = sCertificates.first().androidAttestationExtension!! // ?: throw AttestationValueException("nix gfunden")
        // TODO copy createParsedAttestationRecord code, das nehmen das root am nächsten ist. stoppe sobald gefunden

        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            catchingUnwrapped { keyDescription.verifyApplication(app) }
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

        val receivedChallenge = keyDescription.attestationChallenge
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
        keyDescription.verifyAttestationTime(verificationDate.toInstant())
        keyDescription.verifySecurityLevel()
        keyDescription.verifyBootStateAndSystemImage()
        keyDescription.verifyRollbackResistance()


        keyDescription.verifyAndroidVersion(
            attestedApp.androidVersionOverride,
            attestedApp.patchLevelOverride,
            verificationDate
        )
        return keyDescription
    }

    @Throws(AttestationValueException::class)
    protected abstract fun AttestationKeyDescription.verifyAndroidVersion(
        versionOverride: Int? = null,
        osPatchLevel: PatchLevel?,
        verificationDate: Date
    ): Unit?

    @Throws(AttestationValueException::class)
    protected abstract fun AttestationKeyDescription.verifyRollbackResistance()
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
