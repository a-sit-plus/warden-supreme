package at.asitplus.attestation.android

import at.asitplus.attestation.AttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration.Companion.fromJsonObject
import at.asitplus.attestation.android.AndroidAttestationConfiguration.Companion.fromJsonString
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import at.asitplus.signum.indispensable.toJcaPublicKey
import com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import net.mamoe.yamlkt.Yaml
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.YearMonth
import java.util.*
import kotlin.math.absoluteValue
import kotlin.text.HexFormat

/**
 * Represents a Patch level configuration property.
 * Patch levels are defined as [year] and [month].
 *
 * [maxFuturePatchLevelMonths] indicates how far in the future a patch level parsed from an attestation record can be
 * for it to still be considered valid. It is specified in months and defaults to `1`. This is a sensible default because
 * it is possible that, for example, a July security patch is actually rolled out by the end of June.
 * To ignore patch levels from the future (i.e. to consider all patch levels from the future perfectly valid),
 * set this property to `null`. For testing purposes, this property may also be set to a negative number. Hence, it is
 * represented as a signed integer.
 */
@Serializable
data class PatchLevel @JvmOverloads constructor(
    val year: Int,
    val month: Int,
    val maxFuturePatchLevelMonths: Int? = 1
) {

    constructor(yearMonth: YearMonth, maxFuturePatchLevelMonths: Int? = 1) : this(
        yearMonth.year,
        yearMonth.month.value,
        maxFuturePatchLevelMonths
    )

    val asSingleInt: Int by lazy {
        ("%04d".format(year) + "%02d".format(month)).toInt()
    }

    val asYearMonth: YearMonth by lazy { YearMonth.of(year, month) }

    companion object {

        fun fromSingleInt(yearMothInt: Int, maxFuturePatchLevelMonths: Int? = 1): PatchLevel {
            val year = yearMothInt / 100
            val month = yearMothInt.absoluteValue % 100
            require(month in 1..12) { "$yearMothInt outside valid range" }
            return PatchLevel(year, month, maxFuturePatchLevelMonths)
        }
    }
}


val GOOGLE_RKP_EC_ROOT = TrustedRoot.Certificate(
    X509Certificate.decodeFromPem(
        """
            -----BEGIN CERTIFICATE-----
            MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
            MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
            MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
            WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
            MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
            EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
            G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
            Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
            /zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
            MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
            EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
            uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
            -----END CERTIFICATE-----
            """.trimIndent()
    ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
)

/**
 * Default trust anchors used to verify hardware attestation
 */
val GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS: Set<TrustedRoot> = linkedSetOf(
    //Current RSA ROOT
    TrustedRoot.Certificate(
        X509Certificate.decodeFromPem(
            """
            -----BEGIN CERTIFICATE-----
            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
            w1IdYIg2Wxg7yHcQZemFQg==
            -----END CERTIFICATE-----
            """.trimIndent()
        ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
    ),
    //new Google EC Root
    GOOGLE_RKP_EC_ROOT,
    //Old, but as of 2025 still valid root certificate. Will expire in 2026
    TrustedRoot.Certificate(
        X509Certificate.decodeFromPem(
            """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            """.trimIndent()
        ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
    ),

    //old, but still valid
    TrustedRoot.Certificate(
        X509Certificate.decodeFromPem(
            """
            -----BEGIN CERTIFICATE-----
            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
            ex0SdDrx+tWUDqG8At2JHA==
            -----END CERTIFICATE-----
            """.trimIndent()
        ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
    ),

    //old, but still valid
    TrustedRoot.Certificate(
        X509Certificate.decodeFromPem(
            """
            -----BEGIN CERTIFICATE-----
            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
            mD/vFDkzF+wm7cyWpQpCVQ==
            -----END CERTIFICATE-----
            """.trimIndent()
        ).getOrThrow().toJcaCertificateBlocking().getOrThrow()
    ),
)


/**
 * Default public keys used as trust anchors used to verify hardware attestation
 */
@Deprecated(
    "Supports only public keys",
    replaceWith = ReplaceWith("GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS"),
    DeprecationLevel.ERROR
)
val DEFAULT_HARDWARE_TRUST_ANCHORS = arrayOf(
    KeyFactory.getInstance("RSA")
        .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY))),
    //new Google EC Root
    CryptoPublicKey.decodeFromDer(
        Base64.getDecoder()
            .decode("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr")
    ).toJcaPublicKey().getOrThrow()

)
private val GOOGLE_OLD_TRUST_ANCHORS = arrayOf(
    KeyFactory.getInstance("EC")
        .generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder().decode(
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
                            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="
                )
            )
        ),
    KeyFactory.getInstance("RSA")
        .generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder().decode(
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
                            "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
                            "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
                            "+Vfkl5YLCazOkjWFmwIDAQAB"
                )
            )
        )
)

/**
 * Default trust anchors used to verify software attestation working up to Android 12. Useful for testing.
 * If possible, use older Android images on emulators for testing, EVEN IF THEIR ATTTESTATION ROOT IS EXPIRED, because
 * it has a stable, fixed root cert.
 * Newer Android emulator image keys' are a moving target due to **utterly undocumented key rotation**
 */
val GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12: Set<TrustedRoot> =
    GOOGLE_OLD_TRUST_ANCHORS.map { TrustedRoot.PublicKey(it) }.toSet()

/**
 * Main Android attestation configuration class serving as ground truth for all key and app attestation verifications.
 *
 * @param applications list of applications to be attested
 * @param androidVersion optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
 * **Caution:** Major Android versions increment in steps of ten-thousands. I.e. Android 11 is specified as `110000`
 * Can be overridden for individual apps
 * @param patchLevel optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter
 * @param requireStrongBox optional parameter. Set to `true` if *StrongBox* security level should be required
 * @param allowBootloaderUnlock optional parameter. Set to true if unlocked bootloaders should be allowed.
 * **Attention:** Allowing unlocked bootloaders in production effectively defeats the purpose of app attestation.
 * (but retains the ability to attest whether a key is securely stored in hardware)
 * Useful for debugging/testing.
 * When this is `true`, verified boot state and verified boot key digest checks are skipped, because they only make
 * sense when requiring a locked bootloader.
 * @param requireRollbackResistance optional parameter. Unsupported by most devices.
 * See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
 * @param ignoreLeafValidity optional parameter. Whether to ignore the timely validity of the leaf certificate (looking at you, Samsung!)
 * @param hardwareTrustedRoots Manually specify the trust anchor for HW-attested certificate chains.
 * Defaults to google HW attestation key. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS]
 * @param softwareTrustedRoots Manually specify the trust anchor for SW-attested certificate chains.
 * Defaults to google SW attestation keys. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12]
 * @param disableHardwareAttestation Entirely disable creation of a [HardwareAttestationVerifier].
 * Only change this flag, if you **really** know what you are doing!
 * @param enableSoftwareAttestation Enables software attestation.
 * A [SoftwareAttestationVerifier] can only be instantiated if this flag is set to true.
 * Only change this flag, if you **really** know what you are doing!
 * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
 * [HardwareAttestationVerifier] and a [SoftwareAttestationVerifier].
 */
@Serializable
data class AndroidAttestationConfiguration @JvmOverloads constructor(

    /**
     * List of applications which can be attested. Intentionally a list to prioritise.
     */
    val applications: List<AppData>,

    /**
     * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
     * **Caution:** Major Android versions increment in steps of ten-thousands. I.e. Android 11 is specified as `110000`
     * Can be overridden for individual apps
     */
    val androidVersion: Int? = null,

    /**
     * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
     * Can be overridden for individual apps.
     */
    val patchLevel: PatchLevel? = null,

    /**
     * Set to `true` if *StrongBox* security level should be required.
     * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
     */
    val requireStrongBox: Boolean = false,

    /**
     * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
     * effectively defeats the purpose of Key Attestation. Useful for debugging/testing.
     * When this is `true`, verified boot state and verified boot key digest checks are skipped, because they only make
     * sense when requiring a locked bootloader.
     * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
     */
    val allowBootloaderUnlock: Boolean = false,

    /**
     * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
     */
    val requireRollbackResistance: Boolean = false,

    /**
     * Whether to ignore the timely validity of the leaf certificate
     */
    val ignoreLeafValidity: Boolean = true,
    /**
     *  Tolerance in seconds added to verification date
     */
    val verificationSecondsOffset: Long = 0,

    /**
     * Validity of the attestation statement in seconds. This is not the certificate validity!
     * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
     *
     * **Defaults be set to `null` to ignore attestation statement validity checking.**
     * Hence, even a faulty attestation statement lacking a creation time will verify, but Warden Supreme, by default, ensures freshness through random cryptographic nonces
     */
    val attestationStatementValiditySeconds: Long? = null,

    /**
     * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS]
     */
    val hardwareTrustedRoots: Set<TrustedRoot> = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS,

    /**
     * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12]
     */
    val softwareTrustedRoots: Set<TrustedRoot> = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12,


    /**
     * Entirely disable creation of a [HardwareAttestationVerifier]. Only change this flag, if you **really** know what
     * you are doing!
     * @see enableSoftwareAttestation
     */
    val disableHardwareAttestation: Boolean = false,

    /**
     * Enables software attestation. A [SoftwareAttestationVerifier] can only be instantiated if this flag is set to true.
     * Only change this flag, if you **really** know what you are doing!
     * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
     * [HardwareAttestationVerifier] and a [SoftwareAttestationVerifier].
     */
    val enableSoftwareAttestation: Boolean = false,
    /**
     * [Mandates Remote Key Provisioning (RKP)](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)
     * for attestation checks to pass
     */
    val requireRemoteKeyProvisioning: Boolean = false,

    /**
     * Configures revocation checking. Defaults to checking against the official Google revocation list without Proxy.
     * Intentionally a list to prioritise.
     * @see AndroidRevocationList.HttpLoader.Configuration
     * @see AndroidRevocationList.FileLoader.Configuration
     */
    val revocation: List<AndroidRevocationList.Loader.Configuration<*>> = listOf(AndroidRevocationList.GoogleDefaultLoaderConfig),

    /**
     * Configures which verified boot keys are accepted while requiring a locked bootloader.
     * The default is [VerifiedBootKey.OEM], which accepts vendor-managed `VERIFIED` boot without checking a custom digest.
     * Additional [VerifiedBootKey.Digest] entries allow matching explicit `SELF_SIGNED` verified boot keys by digest.
     * Combining [VerifiedBootKey.OEM] with digest entries accepts both vendor-managed `VERIFIED` boot and explicitly
     * whitelisted `SELF_SIGNED` keys. Omitting [VerifiedBootKey.OEM] accepts only explicitly whitelisted `SELF_SIGNED`
     * keys.
     * This check is only meaningful when [allowBootloaderUnlock] is `false`, because verified boot state and
     * verified boot key digest checks are skipped when unlocked bootloaders are allowed.
     */
    val verifiedBootKeys: Set<VerifiedBootKey> = linkedSetOf(VerifiedBootKey.OEM),

    /**
     * Flag to try out the new supreme parser
     */
    val supremeParser: Boolean = false,

    ) : AttestationConfiguration {

    /**
     * Convenience constructor to attest a single app
     */
    constructor(
        /**
         * The single application to be attested
         */
        singleApp: AppData,

        /**
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of ten-thousands. I.e. Android 11 is specified as `110000`
         * Can be overridden for individual apps
         */
        androidVersion: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         * Can be overridden for individual apps.
         */
        patchLevel: PatchLevel? = null,

        /**
         * Set to `true` if *StrongBox* security level should be required.
         * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing.
         * When this is `true`, verified boot state and verified boot key digest checks are skipped, because they only make
         * sense when requiring a locked bootloader.
         * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = true,

        /**
         *  Tolerance in seconds added to verification date
         */
        verificationSecondsOffset: Long = 0,

        /**
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         *
         * **Can be set to `null` to ignore attestation statement validity checking.** In this case, even a faulty attestation statement lacking a creation time will verify.
         */
        attestationStatementValiditySeconds: Long? = null,

        /**
         * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS]
         */
        hardwareTrustedRoots: Set<TrustedRoot> = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS,

        /**
         * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12]
         */
        softwareTrustedRoots: Set<TrustedRoot> = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12,


        /**
         * Entirely disable creation of a [HardwareAttestationVerifier]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */
        disableHardwareAttestation: Boolean = false,

        /**
         * Enables software attestation. A [SoftwareAttestationVerifier] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [HardwareAttestationVerifier] and a [SoftwareAttestationVerifier].
         */
        enableSoftwareAttestation: Boolean = false,

        /**
         * Configures revocation checking. Defaults to checking against the official Google revocation list without Proxy.
         * Intentionally a list to prioritise.
         * @see AndroidRevocationList.HttpLoader.Configuration
         * @see AndroidRevocationList.FileLoader.Configuration
         */
        revocation: List<AndroidRevocationList.Loader.Configuration<*>> = listOf(AndroidRevocationList.GoogleDefaultLoaderConfig),

        /**
         * [Mandates Remote Key Provisioning (RKP)](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)
         * for attestation checks to pass
         */
        requireRemoteKeyProvisioning: Boolean = false,

        /**
         * @see AndroidAttestationConfiguration.verifiedBootKeys
         */
        verifiedBootKeys: Set<VerifiedBootKey> = linkedSetOf(VerifiedBootKey.OEM),

        /**
         * Flag to try out the new supreme parser
         */
        supremeParser: Boolean = false,
    ) : this(
        listOf(singleApp),
        androidVersion = androidVersion,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareTrustedRoots = hardwareTrustedRoots,
        softwareTrustedRoots = softwareTrustedRoots,
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        revocation = revocation,
        requireRemoteKeyProvisioning = requireRemoteKeyProvisioning,
        verifiedBootKeys = verifiedBootKeys,
        supremeParser = supremeParser,
    )

    /**
     * Constructor used when loading this class from a config file through [Hoplite](https://github.com/sksamuel/hoplite)
     */
    constructor(
        /**
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of ten-thousands. I.e. Android 11 is specified as `110000`
         * Can be overridden for individual apps
         */
        version: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         * Can be overridden for individual apps.
         */
        patchLevel: PatchLevel? = null,

        /**
         * Set to `true` if *StrongBox* security level should be required.
         * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing.
         * When this is `true`, verified boot state and verified boot key digest checks are skipped, because they only make
         * sense when requiring a locked bootloader.
         * **BEWARE** that this switch is utterly useless if [SoftwareAttestationVerifier] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = true,


        /**
         *  Tolerance in seconds added to verification date
         */
        verificationSecondsOffset: Long = 0,

        /**
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         *
         * **Can be set to `null` to ignore attestation statement validity checking.** In this case, even a faulty attestation statement lacking a creation time will verify.
         */
        attestationStatementValiditySeconds: Long? = null,

        /**
         * Entirely disable creation of a [HardwareAttestationVerifier]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */

        disableHardwareAttestation: Boolean = false,

        /**
         * Enables software attestation. A [SoftwareAttestationVerifier] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [HardwareAttestationVerifier] and a [SoftwareAttestationVerifier].
         */
        enableSoftwareAttestation: Boolean = false,


        /**
         * Manually specify the trust anchors for HW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are [GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS]
         */
        hardwareTrustedRoots: Set<ByteArray> = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.derEncoded }.toSet(),

        /**
         * Manually specify the trust anchor for SW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are [GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12]
         */
        softwareTrustedRoots: Set<ByteArray> = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.map { it.derEncoded }.toSet(),

        /**
         * List of applications which can be attested
         */
        apps: List<AppData>,

        /**
         * Configures revocation checking. Defaults to checking against the official Google revocation list without Proxy.
         * @see AndroidRevocationList.HttpLoader.Configuration
         * @see AndroidRevocationList.FileLoader.Configuration
         */
        revocation: List<AndroidRevocationList.Loader.Configuration<*>> = listOf(AndroidRevocationList.GoogleDefaultLoaderConfig),

        /**
         * [Mandates Remote Key Provisioning (RKP)](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)
         * for attestation checks to pass
         */
        requireRemoteKeyProvisioning: Boolean = false,

        /**
         * @see AndroidAttestationConfiguration.verifiedBootKeys
         */
        verifiedBootKeys: Set<VerifiedBootKey> = linkedSetOf(VerifiedBootKey.OEM),

        /**
         * Flag to try out the new supreme parser
         */
        supremeParser: Boolean = false,
    ) : this(
        applications = apps,
        androidVersion = version,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareTrustedRoots = hardwareTrustedRoots.map { TrustedRoot.decode(it) }.toSet(),
        softwareTrustedRoots = softwareTrustedRoots.map { TrustedRoot.decode(it) }.toSet(),
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        revocation = revocation,
        requireRemoteKeyProvisioning = requireRemoteKeyProvisioning,
        verifiedBootKeys = verifiedBootKeys,
        supremeParser = supremeParser,
    )

    /**
     * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
     */
    val osPatchLevel: Int? = patchLevel?.asSingleInt

    /**
     * Specifies a to-be attested app
     *
     * @param packageName Android app package name (e.g. `at.asitplus.demo`)
     * @param signerFingerprints SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing
     * certificate for production play store releases. Being able to specify multiple digests makes it easy to use development
     * builds and production builds in parallel.
     * @param appVersion optional parameter. If set, attestation enforces application version to be greater or equal to this parameter
     * */
    @Serializable
    data class AppData @JvmOverloads constructor(
        /**
         * Android app package name (e.g. `at.asitplus.demo`)
         */
        val packageName: String,
        /**
         * SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
         * production play store releases.
         * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
         */
        val signerFingerprints: Set<@Serializable(with = ByteArrayB64HexSerializer::class) ByteArray>,

        /**
         * optional parameter. If set, attestation enforces application version to be greater or equal to this parameter
         */
        val appVersion: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of ten-thousands. I.e. Android 11 is specified as `110000`
         */
        val androidVersionOverride: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         */
        val patchLevelOverride: PatchLevel? = null,


        /**
         * [Mandates Remote Key Provisioning (RKP)](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)
         * for attestation checks to pass
         */
        val requireRemoteKeyProvisioningOverride: Boolean? = null,

        /**
         * optional parameter. If set, all globally configured trust anchors are discarded and only the trust anchors specified here are used to attest this app.
         */
        val trustedRootOverrides: Set<TrustedRoot>? = null,

        /**
         * optional parameter. If set, this app will require StrongBox security level
         */
        val requireStrongBoxOverride: Boolean? = null,

        /**
         * Optional app-specific override for [AndroidAttestationConfiguration.verifiedBootKeys].
         * This is only meaningful for hardware attestation with a locked bootloader.
         * Use [VerifiedBootKey.OEM] to keep accepting vendor-managed `VERIFIED` boot, add
         * [VerifiedBootKey.Digest] entries to also allow specific `SELF_SIGNED` keys, or omit
         * [VerifiedBootKey.OEM] to require only those explicitly whitelisted `SELF_SIGNED` keys.
         */
        val verifiedBootKeys: Set<VerifiedBootKey>? = null,

        ) {

        init {
            if (signerFingerprints.isEmpty()) throw object :
                AndroidAttestationException("No signature digests specified", null) {}
        }

        /**
         * Internal representation of the patch level as previously contained in the [com.google.android.attestation.ParsedAttestationRecord]
         */
        val osPatchLevel: Int? = patchLevelOverride?.asSingleInt

        /**
         * Builder for more java-friendliness
         * @param packageName Android app package name (e.g. `at.asitplus.demo`)
         * @param signatureDigests  SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
         * production play store releases.
         * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
         */
        class Builder(private val packageName: String, private val signatureDigests: Collection<ByteArray>) {

            /**
             * Builder for more java-friendliness
             * @param packageName Android app package name (e.g. `at.asitplus.demo`)
             * @param signatureDigests  SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
             * production play store releases.
             * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
             */
            constructor(packageName: String, vararg signatureDigests: ByteArray) : this(
                packageName,
                signatureDigests.asList()
            )

            private var appVersion: Int? = null
            private var androidVersionOverride: Int? = null
            private var patchLevelOverride: PatchLevel? = null

            private var trustedRootOverrides: Set<TrustedRoot>? = null

            private var requireRemoteKeyProvisioningOverride: Boolean? = null

            private var requireStrongBoxOverride: Boolean? = null

            /**
             * App-specific override for [AndroidAttestationConfiguration.verifiedBootKeys].
             * This is only meaningful for hardware attestation with a locked bootloader.
             */
            private var verifiedBootKeys: Set<VerifiedBootKey>? = null

            /**
             * @see AppData.appVersion
             */
            fun appVersion(version: Int) = apply { appVersion = version }

            /**
             * @see AppData.androidVersionOverride
             */
            fun androidVersionOverride(version: Int) = apply { androidVersionOverride = version }

            /**
             * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
             */
            fun patchLevelOverride(level: PatchLevel) = apply { patchLevelOverride = level }

            /**
             * optional parameter. If set, all globally configured trust anchors are discarded and only the trust anchors specified here are used to attest this app.
             */
            @JvmName("overrideTrustedRootKeys")
            fun trustedRootOverrides(trustedRoots: Set<PublicKey>) =
                apply { trustedRootOverrides = trustedRoots.map { TrustedRoot.PublicKey(it) }.toSet() }

            /**
             * optional parameter. If set, all globally configured trust anchors are discarded and only the trust anchors specified here are used to attest this app.
             */
            fun trustedRootOverrides(trustedRoots: Set<TrustedRoot>) = apply { trustedRootOverrides = trustedRoots }

            /**
             * [Mandates Remote Key Provisioning (RKP)](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning)
             * for attestation checks to pass
             */
            fun requireRemoteProvisioningOverride(required: Boolean) =
                apply { requireRemoteKeyProvisioningOverride = required }

            /**
             * optional parameter. If set, this app will require StrongBox security level
             */
            fun requireStrongBoxOverride(required: Boolean) = apply { requireStrongBoxOverride = required }

            /**
             * @see AppData.verifiedBootKeys
             */
            fun verifiedBootKeys(keys: Set<VerifiedBootKey>) = apply { verifiedBootKeys = keys }

            fun build() =
                AppData(
                    packageName,
                    signatureDigests.toSet(),
                    appVersion,
                    androidVersionOverride,
                    patchLevelOverride,
                    requireRemoteKeyProvisioningOverride,
                    trustedRootOverrides,
                    requireStrongBoxOverride,
                    verifiedBootKeys,
                )
        }

        override fun toString(): String {
            return "AppData(" +
                    "packageName='$packageName', " +
                    "signatureDigests=${signerFingerprints.joinToString { it.toHexString() }}, " +
                    "appVersion=$appVersion, " +
                    "androidVersionOverride=$androidVersionOverride, " +
                    "patchLevelOverride=$patchLevelOverride, " +
                    "osPatchLevel=$osPatchLevel" +
                    ")"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AppData) return false

            if (appVersion != other.appVersion) return false
            if (androidVersionOverride != other.androidVersionOverride) return false
            if (osPatchLevel != other.osPatchLevel) return false
            if (packageName != other.packageName) return false
            if (!(signerFingerprints contentEqualsIfArray other.signerFingerprints)) return false

            if (patchLevelOverride != other.patchLevelOverride) return false

            if (requireRemoteKeyProvisioningOverride != other.requireRemoteKeyProvisioningOverride) return false

            if (trustedRootOverrides != other.trustedRootOverrides) return false

            if (requireStrongBoxOverride != other.requireStrongBoxOverride) return false
            if (verifiedBootKeys != other.verifiedBootKeys) return false

            return true
        }

        override fun hashCode(): Int {
            var result = appVersion ?: 0
            result = 31 * result + (androidVersionOverride ?: 0)
            result = 31 * result + (osPatchLevel ?: 0)
            result = 31 * result + packageName.hashCode()
            result = 31 * result + signerFingerprints.contentHashCodeIfArray()
            result = 31 * result + (patchLevelOverride?.hashCode() ?: 0)
            result = 31 * result + (trustedRootOverrides?.hashCode() ?: 0)
            result = 31 * result + (requireRemoteKeyProvisioningOverride?.hashCode() ?: 0)
            result = 31 * result + (requireStrongBoxOverride?.hashCode() ?: 0)
            result = 31 * result + (verifiedBootKeys?.hashCode() ?: 0)
            return result
        }

    }

    init {
        if (hardwareTrustedRoots.isEmpty() && softwareTrustedRoots.isEmpty())
            throw object : AndroidAttestationException("No trust anchors configured", null) {}

        if (applications.isEmpty()) throw object : AndroidAttestationException("No apps configured", null) {}
        if (verifiedBootKeys.isEmpty()) throw object :
            AndroidAttestationException("No verified boot key policy configured", null) {}
        if (applications.any { it.verifiedBootKeys?.isEmpty() == true })
            throw object :
                AndroidAttestationException("App-specific verified boot key policy must not be empty", null) {}
        if (disableHardwareAttestation && !enableSoftwareAttestation)
            throw object : AndroidAttestationException(
                "Neither hardware, nor software attestation enabled", null
            ) {}
        attestationStatementValiditySeconds?.let {
            if (it < 0) throw object :
                AndroidAttestationException("Attestation statement validity must not be negative", null) {}
        }
    }

    /**
     * Builder to construct an [AndroidAttestationConfiguration] in a java-friendly way
     * @param applications applications to be attested
     */
    class Builder(private val applications: List<AppData>) {

        /**
         * convenience constructor to attest a [singleApp]
         */
        constructor(singleApp: AppData) : this(listOf(singleApp))

        private var androidVersion: Int? = null
        private var patchLevel: PatchLevel? = null
        private var requireStrongBox: Boolean = false
        private var bootloaderUnlockAllowed: Boolean = false
        private var rollbackResitanceRequired: Boolean = false
        private var ignoreLeafValidity: Boolean = true
        private var hardwareTrustedRoots =
            mutableSetOf<TrustedRoot>(*GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.toTypedArray())
        private var softwareTrustedRoots =
            mutableSetOf<TrustedRoot>(*GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.toTypedArray())
        private var verificationSecondsOffset = 0L
        private var attestationStatementValiditySeconds: Long? = null
        private var disableHwAttestation: Boolean = false
        private var enableSwAttestation: Boolean = false
        private var revocation: List<AndroidRevocationList.Loader.Configuration<*>> =
            listOf(AndroidRevocationList.GoogleDefaultLoaderConfig)
        private var requireRemoteKeyProvisioning: Boolean = false
        private var verifiedBootKeys: Set<VerifiedBootKey> = linkedSetOf(VerifiedBootKey.OEM)
        private var supremeParser: Boolean = false

        /**
         * specifies a minimum Android version
         * @see AndroidAttestationConfiguration.androidVersion
         */
        fun androidVersion(version: Int) = apply { androidVersion = version }

        /**
         * @see PatchLevel
         */
        fun patchLevel(lvl: PatchLevel) = apply { patchLevel = lvl }

        /**
         * @see AndroidAttestationConfiguration.requireStrongBox
         */
        fun requireStrongBox() = apply { requireStrongBox = true }

        /**
         * @see AndroidAttestationConfiguration.allowBootloaderUnlock
         *
         * Allowing unlocked bootloaders also disables verified boot state and verified boot key checks.
         */
        fun allowBootloaderUnlock() = apply { bootloaderUnlockAllowed = true }

        /**
         * @see AndroidAttestationConfiguration.requireRollbackResistance
         */
        fun requireRollbackResistance() = apply { rollbackResitanceRequired = true }

        /**
         * set [AndroidAttestationConfiguration.ignoreLeafValidity] to false
         */
        fun enforceLeafValidity() = apply { ignoreLeafValidity = false }

        /**
         * @see AndroidAttestationConfiguration.hardwareTrustedRoots
         */
        @JvmName("hardwareAttestationTrustAnchorPublicKeys")
        fun hardwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { hardwareTrustedRoots.apply { clear(); addAll(anchors.map { TrustedRoot.PublicKey(it) }) } }

        /**
         * adds a single hardware attestation trust anchor
         * @see AndroidAttestationConfiguration.hardwareTrustedRoots
         */
        @JvmName("addHardwareAttestationTrustAnchorPublicKey")
        fun addHardwareAttestationTrustAnchor(anchor: PublicKey) =
            apply { hardwareTrustedRoots += TrustedRoot.PublicKey(anchor) }

        /**
         * @see AndroidAttestationConfiguration.softwareTrustedRoots
         */
        @JvmName("softwareAttestationTrustAnchorPublicKeys")
        fun softwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { softwareTrustedRoots.apply { clear(); addAll(anchors.map { TrustedRoot.PublicKey(it) }) } }

        /**
         * adds a single software attestation trust anchor
         * @see AndroidAttestationConfiguration.softwareTrustedRoots
         */
        @JvmName("addSoftwareAttestationTrustAnchorPublicKey")
        fun addSoftwareAttestationTrustAnchor(anchor: PublicKey) =
            apply { softwareTrustedRoots += TrustedRoot.PublicKey(anchor) }


        /**
         * @see AndroidAttestationConfiguration.hardwareTrustedRoots
         */
        fun hardwareTrustedRoots(anchors: Set<TrustedRoot>) =
            apply { hardwareTrustedRoots.apply { clear(); addAll(anchors) } }

        /**
         * adds a single hardware attestation trust anchor
         * @see AndroidAttestationConfiguration.hardwareTrustedRoots
         */
        fun addHardwareTrustedRoot(anchor: TrustedRoot) = apply { hardwareTrustedRoots += anchor }

        /**
         * @see AndroidAttestationConfiguration.softwareTrustedRoots
         */
        fun softwareTrustedRoots(anchors: Set<TrustedRoot>) =
            apply { softwareTrustedRoots.apply { clear(); addAll(anchors) } }

        /**
         * adds a single software attestation trust anchor
         * @see AndroidAttestationConfiguration.softwareTrustedRoots
         */
        fun addSoftwareTrustedRoot(anchor: TrustedRoot) = apply { softwareTrustedRoots += anchor }

        /**
         * @see AndroidAttestationConfiguration.verificationSecondsOffset
         */
        fun verificationSecondsOffset(seconds: Long) = apply { verificationSecondsOffset = seconds }

        /**
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         *
         * **Can be set to `null` to ignore attestation statement validity checking.** In this case, even a faulty attestation statement lacking a creation time will verify.
         */
        fun attestationStatementValiditySeconds(seconds: Long?) =
            apply { attestationStatementValiditySeconds = seconds }

        /**
         * @see AndroidAttestationConfiguration.disableHardwareAttestation
         */
        fun disableHardwareAttestation() = apply { disableHwAttestation = true }

        /**
         * @see AndroidAttestationConfiguration.enableSoftwareAttestation
         */
        fun enableSoftwareAttestation() = apply { enableSwAttestation = true }

        /**
         * Configures revocation checking. Defaults to checking against the official Google revocation list without Proxy.
         * Intentionally a list to prioritise.
         * @see AndroidRevocationList.HttpLoader.Configuration
         * @see AndroidRevocationList.FileLoader.Configuration
         */
        fun revocation(revocation: List<AndroidRevocationList.Loader.Configuration<*>>) = apply {
            this.revocation = revocation
        }

        /**
         * @see at.asitplus.attestation.android.AndroidAttestationConfiguration.requireRemoteKeyProvisioning
         */
        fun requireRemoteKeyProvisioning(required: Boolean) = apply { requireRemoteKeyProvisioning = required }

        /**
         * @see AndroidAttestationConfiguration.verifiedBootKeys
         */
        fun verifiedBootKeys(keys: Set<VerifiedBootKey>) = apply { verifiedBootKeys = keys }

        /**
         * Flag to try out the new supreme parser
         */
        fun supremeParser(supremeParser: Boolean) = apply { this.supremeParser = supremeParser }

        fun build() = AndroidAttestationConfiguration(
            applications = applications,
            androidVersion = androidVersion,
            patchLevel = patchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = bootloaderUnlockAllowed,
            requireRollbackResistance = rollbackResitanceRequired,
            ignoreLeafValidity = ignoreLeafValidity,
            hardwareTrustedRoots = hardwareTrustedRoots,
            softwareTrustedRoots = softwareTrustedRoots,
            verificationSecondsOffset = verificationSecondsOffset,
            attestationStatementValiditySeconds = attestationStatementValiditySeconds,
            disableHardwareAttestation = disableHwAttestation,
            enableSoftwareAttestation = enableSwAttestation,
            revocation = revocation,
            requireRemoteKeyProvisioning = requireRemoteKeyProvisioning,
            verifiedBootKeys = verifiedBootKeys,
            supremeParser = supremeParser,
        )

    }

    override fun toString(): String {
        return "AndroidAttestationConfiguration(" +
                "applications=$applications, " +
                "androidVersion=$androidVersion, " +
                "patchLevel=$patchLevel, " +
                "requireStrongBox=$requireStrongBox, " +
                "allowBootloaderUnlock=$allowBootloaderUnlock, " +
                "requireRollbackResistance=$requireRollbackResistance, " +
                "ignoreLeafValidity=$ignoreLeafValidity, " +
                "hardwareAttestationTrustAnchors=${hardwareTrustedRoots.joinToString { it.derEncoded.encodeBase64() }}, " +
                "softwareAttestationTrustAnchors=${softwareTrustedRoots.joinToString { it.derEncoded.encodeBase64() }}, " +
                "verificationSecondsOffset=$verificationSecondsOffset, " +
                "attestationStatementValiditySeconds=$attestationStatementValiditySeconds, " +
                "disableHardwareAttestation=$disableHardwareAttestation, " +
                "enableSoftwareAttestation=$enableSoftwareAttestation, " +
                "revocation=$revocation, " +
                "verifiedBootKeys=$verifiedBootKeys, " +
                "osPatchLevel=$osPatchLevel, " +
                "supremeParser=$supremeParser" +
                ")"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AndroidAttestationConfiguration) return false

        if (androidVersion != other.androidVersion) return false
        if (requireStrongBox != other.requireStrongBox) return false
        if (allowBootloaderUnlock != other.allowBootloaderUnlock) return false
        if (requireRollbackResistance != other.requireRollbackResistance) return false
        if (ignoreLeafValidity != other.ignoreLeafValidity) return false
        if (verificationSecondsOffset != other.verificationSecondsOffset) return false
        if (attestationStatementValiditySeconds != other.attestationStatementValiditySeconds) return false
        if (disableHardwareAttestation != other.disableHardwareAttestation) return false
        if (enableSoftwareAttestation != other.enableSoftwareAttestation) return false
        if (osPatchLevel != other.osPatchLevel) return false
        if (applications != other.applications) return false
        if (patchLevel != other.patchLevel) return false

        if (hardwareTrustedRoots != other.hardwareTrustedRoots) return false
        if (softwareTrustedRoots != other.softwareTrustedRoots) return false

        if (revocation != other.revocation) return false

        if (requireRemoteKeyProvisioning != other.requireRemoteKeyProvisioning) return false
        if (verifiedBootKeys != other.verifiedBootKeys) return false
        if (supremeParser != other.supremeParser) return false

        return true
    }

    override fun hashCode(): Int {
        var result = androidVersion ?: 0
        result = 31 * result + requireStrongBox.hashCode()
        result = 31 * result + allowBootloaderUnlock.hashCode()
        result = 31 * result + requireRollbackResistance.hashCode()
        result = 31 * result + ignoreLeafValidity.hashCode()
        result = 31 * result + verificationSecondsOffset.toInt()
        attestationStatementValiditySeconds?.let { result = 31 * result + attestationStatementValiditySeconds.toInt() }
        result = 31 * result + disableHardwareAttestation.hashCode()
        result = 31 * result + enableSoftwareAttestation.hashCode()
        result = 31 * result + (osPatchLevel ?: 0)
        result = 31 * result + applications.hashCode()
        result = 31 * result + (patchLevel?.hashCode() ?: 0)
        result = 31 * result + hardwareTrustedRoots.hashCode()
        result = 31 * result + softwareTrustedRoots.hashCode()
        result = 31 * result + revocation.hashCode()
        result = 31 * result + requireRemoteKeyProvisioning.hashCode()
        result = 31 * result + verifiedBootKeys.hashCode()
        result = 31 * result + supremeParser.hashCode()
        return result
    }

    /**
     * Serialises this config into its canonical form (JSON). Can be loaded using [fromJsonString] afterwards.
     */
    override fun toJsonString(): String = jsonDebug.encodeToString(this)

    /**
     * Serialises this config into its canonical form (YAML). Can be loaded using [fromJsonString] afterwards.
     */
    override fun toYamlString(): String = yaml.encodeToString(this)

    /**
     * Serialises this config into a [JsonObject]. Can be loaded using [fromJsonObject] afterwards.
     */
    override fun toJsonElement(): JsonObject = jsonDebug.encodeToJsonElement(this).jsonObject

    companion object : AttestationConfiguration.Reader<AndroidAttestationConfiguration> {

        private val yaml by lazy {
            Yaml {
                serializersModule = AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e }
            }
        }

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        override fun fromJsonString(jsonRepresentation: String): AndroidAttestationConfiguration =
            jsonDebug.decodeFromString<AndroidAttestationConfiguration>(jsonRepresentation)

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        override fun fromYamlString(yamlRepresentation: String): AndroidAttestationConfiguration =
            yaml.decodeFromString(yamlRepresentation)

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonElement].
         */
        override fun fromJsonObject(jsonRepresentation: JsonElement): AndroidAttestationConfiguration =
            jsonDebug.decodeFromJsonElement<AndroidAttestationConfiguration>(jsonRepresentation)

    }
}

/**
 * Leniently (ignore case, and whitespace andd `:`) parse hex to bytes
 */
fun String.parseHex(): ByteArray =
    this.filterNot { it.isWhitespace() }.replace(":", "").lowercase().hexToByteArray(HexFormat.Default)

@Serializable(with = VerifiedBootKeySerializer::class)
sealed interface VerifiedBootKey {
    @Serializable
    data object OEM : VerifiedBootKey {
        const val name = "OEM"
        override fun toString(): String = name
    }

    @Serializable
    class Digest(@Serializable(with = ByteArrayHexStringSerializer::class) val value: ByteArray) : VerifiedBootKey {
        override fun equals(other: Any?): Boolean = other is Digest && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()

        override fun toString(): String = value.toHexString().chunked(2).joinToString(":")
    }

    companion object {
        fun fromString(str: String): VerifiedBootKey {
            val value = str.trim()
            return if (value.equals(OEM.name, ignoreCase = true)) OEM
            else Digest(value.parseHex())
        }
    }
}

object VerifiedBootKeySerializer : KSerializer<VerifiedBootKey> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("VerifiedBootKeySerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: VerifiedBootKey) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): VerifiedBootKey = VerifiedBootKey.fromString(decoder.decodeString())

}

object ByteArrayHexStringSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayHexStringSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.toHexString().chunked(2).joinToString(":"))
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().parseHex()
    }

}

object ByteArrayB64HexSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayB64HexSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) = ByteArrayHexStringSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): ByteArray {
        val string = decoder.decodeString()
        return if (string.length < 64) string.decodeToByteArray(Base64UrlStrict)
        else string.parseHex()
    }
}