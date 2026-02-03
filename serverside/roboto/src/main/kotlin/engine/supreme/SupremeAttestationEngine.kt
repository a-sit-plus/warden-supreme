package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.toBigInteger
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.datetime.Month
import kotlinx.datetime.TimeZone
import kotlinx.datetime.YearMonth
import kotlinx.datetime.number
import kotlinx.datetime.toLocalDateTime
import java.security.cert.X509Certificate
import kotlin.time.Instant

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

    override val AttestationKeyDescription.createdAt: Instant?
        get() = hardwareEnforced.creationDateTime?.getOrNull()?.timestamp
            ?: softwareEnforced.creationDateTime?.getOrNull()?.timestamp

    override val AuthorizationList.appIdForDiagnostics: AttestationValue<AuthorizationList.AttestationApplicationId>?
        get() = attestationApplicationId

    @Throws(Throwable::class)
    override fun AuthorizationList.findMatchingPackageVersions(packageName: String): List<UInt> =
        attestationApplicationId?.getOrThrow()?.packageInfos?.filter {
            it.packageName == packageName
        }?.map { it.version } ?: emptyList()

    @get:Throws(Throwable::class)
    override val AuthorizationList.signerFingerprints: Set<ByteArray>?
        get() = attestationApplicationId?.getOrThrow()?.signatureDigests

//TODO: unify
    override fun AuthorizationList.verifyAndroidVersionFromAuthList(
        versionOverride: Int?,
        patchLevel: PatchLevel?,
        verificationDate: Instant
    ) {
        catchingUnwrapped {
            (versionOverride ?: attestationConfiguration.androidVersion)?.let {
                val osVersionFromRecord = osVersion?.getOrNull()?.intValue?.toBigInteger()
                if ((osVersionFromRecord == null) || osVersionFromRecord < BigInteger(it)) throw AttestationValueException(
                    "Android version not supported: $osVersionFromRecord (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION,
                    expectedValue = it,
                    actualValue = osVersion
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                val fromRecord = osPatchLevelLenient

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
                    val fromAttestation = osPatchLevelLenient

                    val currentYearMonth =
                        verificationDate.toLocalDateTime(TimeZone.UTC).let { YearMonth(it.year, it.month) }
                    val difference = fromAttestation?.let { monthsBetween(currentYearMonth, it) }
                    if ((difference == null) || (difference > maxFuturePatchLevelMonths)
                    ) throw AttestationValueException(
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
    }
//TODO: unify
    override fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        val parsedRootOfTrust = rootOfTrust?.getOrNull() ?: throw AttestationValueException(
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

        if (parsedRootOfTrust.verifiedBootState != AuthorizationList.RootOfTrust.VerifiedBootState.Verified
        ) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY,
            expectedValue = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
            actualValue = parsedRootOfTrust.verifiedBootState
        )
    }

    override val AuthorizationList.rollbackResistant: Boolean
        get() = (rollbackResistant?.getOrNull() ?: rollbackResistance?.getOrNull()) != null

    override val AttestationKeyDescription.attestationSecLevel: GeneralizedSecurityLevel
        get() = when (attestationSecurityLevel) {
            AttestationKeyDescription.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            AttestationKeyDescription.SecurityLevel.STRONGBOX -> GeneralizedSecurityLevel.STRONGBOX
        }

    override val AttestationKeyDescription.keymasterSecLevel: GeneralizedSecurityLevel
        get() = when (keymasterSecurityLevel) {
            AttestationKeyDescription.SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
            AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
            AttestationKeyDescription.SecurityLevel.STRONGBOX -> GeneralizedSecurityLevel.STRONGBOX
        }


    class Hardware(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean,
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        override val type by lazy { HardwareEngine() }

    }

    class Software(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
    ) : SupremeAttestationEngine(attestationConfiguration, verifyChallenge) {
        override val type by lazy { SoftwareEngine() }
    }

}


fun monthsBetween(start: YearMonth, end: YearMonth): Int =
    (end.year - start.year) * 12 + (end.month.number - start.month.number)
