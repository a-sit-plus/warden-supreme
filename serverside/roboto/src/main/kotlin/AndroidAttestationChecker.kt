package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.Security
import java.security.cert.*
import java.time.Duration
import java.time.Instant
import java.time.YearMonth
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.jvm.optionals.getOrNull

abstract class AndroidAttestationChecker(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    private val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {
    companion object {
        init {
            Security.addProvider(KeyAttestationProvider())
        }

        private fun getValidator() = CertPathValidator.getInstance("KeyAttestation")
    }

    private val newPkixCertPathValidator = getValidator()

    private val revocationListClient = HttpClient(CIO) { setup(attestationConfiguration.httpProxy) }

    @Throws(CertificateInvalidException::class, RevocationException::class)
    private fun List<X509Certificate>.verifyCertificateChain(
        verificationDate: Date,
        actualTrustAnchors: Collection<PublicKey>
    ) {
        catchingUnwrapped { verifyRootCertificate(verificationDate, actualTrustAnchors) }
            .onFailure {
                throw if (it is CertificateInvalidException) it else CertificateInvalidException.InvalidRoot(
                    message = "could not verify root certificate (valid from: ${last().notBefore} to ${last().notAfter}), verification date: $verificationDate",
                    cause = it,
                    reason = if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST,
                    certificateChain = this,
                    invalidCertificate = last()
                )
            }
        val revocationStatusList = catchingUnwrapped { RevocationList.fromGoogleServer(client = revocationListClient) }
            .getOrElse {
                throw RevocationException.ListUnavailable(
                    "could not download revocation information",
                    it
                )
            }
        val certificateChain =
            if (attestationConfiguration.ignoreLeafValidity) mapIndexed { i, cert ->
                if (i == 0) EternalX509Certificate(cert) else cert
            } else this

        certificateChain.reversed().zipWithNext { parent, certificate ->
            verifyCertificatePair(certificate, parent, verificationDate, revocationStatusList, certificateChain)
        }

        //now we double-check against the new validator to rule out manipulations of the certificate chain
        catchingUnwrapped {
            newPkixCertPathValidator.validate(
                KeyAttestationCertPath(certificateChain),
                PKIXParameters(
                    setOf(TrustAnchor(certificateChain.last(), null))
                ).apply {
                    date = verificationDate
                    isRevocationEnabled =
                        false //we check manually as per the official documentation, and we've done that already
                }
            )
        }.onFailure {
            throw CertificateInvalidException(
                message = "PKIX cert path validation failed",
                it,
                reason = CertificateInvalidException.Reason.TRUST, //we have ruled out time beforehand
                certificateChain = certificateChain,
                invalidCertificate = null
            )
        }

    }

    @Throws(RevocationException::class, CertificateInvalidException::class)
    private fun verifyCertificatePair(
        certificate: X509Certificate,
        parent: X509Certificate,
        verificationDate: Date,
        statusList: RevocationList,
        fullChainForDebugging: List<X509Certificate>
    ) {
        catchingUnwrapped {
            certificate.checkValidity(verificationDate)
            certificate.verify(parent.publicKey)
        }.onFailure {
            throw CertificateInvalidException(
                message = "Certificate ${certificate.serialNumber} could not be verified",
                cause = it,
                reason = if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST,
                certificateChain = fullChainForDebugging,
                invalidCertificate = certificate
            )
        }
        catchingUnwrapped {
            statusList.isRevoked(certificate.serialNumber)
        }.onSuccess {
            if (it)
                throw RevocationException.Revoked(
                    "Certificate ${certificate.serialNumber} revoked",
                    certificateChain = fullChainForDebugging,
                    revokedCertificate = certificate
                )
        }.onFailure {
            throw RevocationException.ListUnavailable(
                "Could not init revocation list",
                it
            )
        }
    }

    private fun List<X509Certificate>.verifyRootCertificate(
        verificationDate: Date,
        actualTrustAnchors: Collection<PublicKey>,
    ) {
        val root = last()
        root.checkValidity(verificationDate)
        val matchingTrustAnchor = actualTrustAnchors
            .firstOrNull { root.publicKey.encoded.contentEquals(it.encoded) }
            ?: run {
                throw if (DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default HARDWARE Root",
                        invalidCertificate = root,
                        certificateChain = this,
                        rootCertStage = CertificateInvalidException.OtherMatchingRoot.Stage.HARDWARE
                    )
                else if (DEFAULT_SOFTWARE_TRUST_ANCHORS.map { it.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default SOFTWARE Root",
                        invalidCertificate = root,
                        certificateChain = this,
                        rootCertStage = CertificateInvalidException.OtherMatchingRoot.Stage.SOFTWARE
                    )
                else CertificateInvalidException.NoMatchingRoot(
                    "No matching root certificate. Found an unknown Root",
                    invalidCertificate = root,
                    certificateChain = this
                )
            }
        root.verify(matchingTrustAnchor)
    }

    protected abstract val trustAnchors: Collection<PublicKey>

    protected open fun ParsedAttestationRecord.verifyAttestationTime(verificationDate: Instant) {
        var checkTime = verificationDate.plusSeconds(attestationConfiguration.verificationSecondsOffset.toLong())
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
    private fun ParsedAttestationRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
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
                    application.signatureDigests.any { it.contentEquals(fromAttestation.toByteArray()) }
                }) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
                    expectedValue = application.signatureDigests,
                    actualValue = softwareEnforced().attestationApplicationId().get().signatureDigests().map { it.toByteArray() }
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
    protected abstract fun ParsedAttestationRecord.verifyAndroidVersion(
        versionOverride: Int? = null,
        osPatchLevel: PatchLevel?,
        verificationDate: Date
    ): Unit?

    @Throws(AttestationValueException::class)
    protected fun AuthorizationList.verifyAndroidVersion(
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
                val calendar = Calendar.getInstance(TimeZone.getTimeZone(ZoneOffset.UTC)).apply { time = verificationDate }
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
    protected abstract fun ParsedAttestationRecord.verifyBootStateAndSystemImage()

    @Throws(AttestationValueException::class)
    protected fun AuthorizationList.verifySystemLocked() {
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
    protected abstract fun ParsedAttestationRecord.verifyRollbackResistance()

    @Throws(AttestationValueException::class)
    protected fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!rollbackResistance()) throw AttestationValueException(
                "No rollback resistance",
                reason = AttestationValueException.Reason.ROLLBACK_RESISTANCE,
                expectedValue = true,
                actualValue = false
            )
    }

    /**
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    fun collectDebugInfo(
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
    open fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord {
        val actualVerificationDate =
            Date.from(verificationDate.toInstant().plusSeconds(attestationConfiguration.verificationSecondsOffset))


        //do this before we check everything else to actually identify the app we're having here
        val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates)
        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            catchingUnwrapped { parsedAttestationRecord.verifyApplication(app) }
        }.let {
            it.entries.firstOrNull { (_, result) -> result.isSuccess } ?: it.values.first().exceptionOrNull()!!
                .let { throw it }
        }.key

        val thisAppsTrustAnchors = attestedApp.trustAnchorOverrides ?: trustAnchors
        certificates.verifyCertificateChain(actualVerificationDate, thisAppsTrustAnchors)

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
    protected abstract fun ParsedAttestationRecord.verifySecurityLevel()

    /**
     * taken and adapted from [com.google.android.attestation.CertificateRevocationStatus] to separate downloading and checking
     */
    class RevocationList(json: JsonObject) {
        private val entries by lazy { json["entries"]?.jsonObject ?: throw IOException() }
        fun isRevoked(
            serialNumber: BigInteger
        ): Boolean {
            val serialNumberNormalised = serialNumber.toString(16).lowercase(Locale.getDefault())
            return entries[serialNumberNormalised] != null //any entry is a red flag!
        }

        companion object {
            @JvmStatic
            private val client by lazy { HttpClient(CIO) { setup(null) } }

            @OptIn(ExperimentalSerializationApi::class)
            @JvmStatic
            fun from(source: InputStream) = RevocationList(json.decodeFromStream(source))

            @Throws(Throwable::class)
            @JvmStatic
            @JvmOverloads
            fun fromGoogleServer(client: HttpClient = this.client) =
                runBlocking {
                    RevocationList(client.get("https://android.googleapis.com/attestation/status").body<JsonObject>())
                }
        }
    }
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
