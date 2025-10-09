package at.asitplus.attestation.android

import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyHardwareAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyNougatHybridAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacySoftwareAttestationEngine
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY
import io.ktor.util.*
import kotlinx.serialization.Serializable
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.YearMonth
import java.util.*
import kotlin.math.absoluteValue

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

/**
 * Default trust anchors used to verify hardware attestation
 */
val DEFAULT_HARDWARE_TRUST_ANCHORS = arrayOf(
    KeyFactory.getInstance("RSA")
        .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY)))
)


/**
 * Default trust anchors used to verify software attestation
 */
val DEFAULT_SOFTWARE_TRUST_ANCHORS = arrayOf(
    //SW_EC_ROOT
    KeyFactory.getInstance("EC")
        .generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder().decode(
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
                            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="
                )
            )
        ),
    //HW EC ROOT
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
 * Useful for debugging/testing
 * @param requireRollbackResistance optional parameter. Unsupported by most devices.
 * See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
 * @param ignoreLeafValidity optional parameter. Whether to ignore the timely validity of the leaf certificate (looking at you, Samsung!)
 * @param hardwareAttestationTrustAnchors Manually specify the trust anchor for HW-attested certificate chains.
 * Defaults to google HW attestation key. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
 * @param softwareAttestationTrustAnchors Manually specify the trust anchor for SW-attested certificate chains.
 * Defaults to google SW attestation keys. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
 * @param disableHardwareAttestation Entirely disable creation of a [LegacyHardwareAttestationEngine].
 * Only change this flag, if you **really** know what you are doing!
 * @param enableNougatAttestation Enables hybrid attestation.
 * [LegacyNougatHybridAttestationEngine] can only be instantiated if this flag is set to true.
 * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
 * devices only support hardware-backed key attestation, but provide no indication about the OS state.
 * Hence, app-attestation cannot be trusted, but key attestation still can.
 * @param enableSoftwareAttestation Enables software attestation.
 * A [LegacySoftwareAttestationEngine] can only be instantiated if this flag is set to true.
 * Only change this flag, if you **really** know what you are doing!
 * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
 * [LegacyHardwareAttestationEngine] and a [LegacySoftwareAttestationEngine].
 */
@Serializable
data class AndroidAttestationConfiguration @JvmOverloads constructor(

    /**
     * List of applications which can be attested
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
    internal val patchLevel: PatchLevel? = null,

    /**
     * Set to `true` if *StrongBox* security level should be required.
     * **BEWARE** that this switch is utterly useless if [LegacyNougatHybridAttestationEngine] of [LegacySoftwareAttestationEngine] is used
     */
    val requireStrongBox: Boolean = false,

    /**
     * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
     * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
     * **BEWARE** that this switch is utterly useless if [LegacyNougatHybridAttestationEngine] of [LegacySoftwareAttestationEngine] is used
     */
    val allowBootloaderUnlock: Boolean = false,

    /**
     * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
     */
    val requireRollbackResistance: Boolean = false,

    /**
     * Whether to ignore the timely validity of the leaf certificate
     */
    val ignoreLeafValidity: Boolean = false,

    /**
     * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
     */
    val hardwareAttestationTrustAnchors: Set<@Serializable(with = PubKeyBasePemSerializer::class) PublicKey>
    = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS),

    /**
     * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
     */
    val softwareAttestationTrustAnchors: Set<@Serializable(with = PubKeyBasePemSerializer::class) PublicKey>
    = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS),

    /**
     *  Tolerance in seconds added to verification date
     */
    val verificationSecondsOffset: Long = 0,

    /**
     * Validity of the attestation statement in seconds. This is not the certificate validity!
     * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
     *
     * **Can be set to `null` to ignore attestation statement validity checking.** In this case, even a faulty attestation statement lacking a creation time will verify.
     */
    val attestationStatementValiditySeconds: Long? = 5 * 60,

    /**
     * Entirely disable creation of a [LegacyHardwareAttestationEngine]. Only change this flag, if you **really** know what
     * you are doing!
     * @see enableSoftwareAttestation
     */
    val disableHardwareAttestation: Boolean = false,

    /**
     * Enables hybrid attestation. A [LegacyNougatHybridAttestationEngine] can only be instantiated if this flag is set to true.
     * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
     * devices only support hardware-backed key attestation, but provide no indication about the OS state.
     * Hence, app-attestation cannot be trusted, but key attestation still can.
     */
    val enableNougatAttestation: Boolean = false,

    /**
     * Enables software attestation. A [LegacySoftwareAttestationEngine] can only be instantiated if this flag is set to true.
     * Only change this flag, if you **really** know what you are doing!
     * Enabling this flag, while keeping [disableHardwareAttestation] `false` makes is possible to instantiate both a
     * [LegacyHardwareAttestationEngine] and a [LegacySoftwareAttestationEngine].
     */
    val enableSoftwareAttestation: Boolean = false,

    /**
     * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
     */
    val httpProxy: String? = null,

    ) {

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
         * **BEWARE** that this switch is utterly useless if [egacyNougatHybridAttestationChecker] of [LegacySoftwareAttestationEngine] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
         * **BEWARE** that this switch is utterly useless if [LegacyNougatHybridAttestationEngine] of [LegacySoftwareAttestationEngine] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = false,

        /**
         * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
         */
        hardwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS),

        /**
         * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
         */
        softwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS),

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
        attestationStatementValiditySeconds: Long? = 5 * 60,

        /**
         * Entirely disable creation of a [LegacyHardwareAttestationEngine]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */
        disableHardwareAttestation: Boolean = false,

        /**
         * Enables hybrid attestation. A [LegacyNougatHybridAttestationEngine] can only be instantiated if this flag is set to true.
         * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
         * devices only support hardware-backed key attestation, but provide no indication about the OS state.
         * Hence, app-attestation cannot be trusted, but key attestation still can.
         */
        enableNougatAttestation: Boolean = false,

        /**
         * Enables software attestation. A [LegacySoftwareAttestationEngine] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [LegacyHardwareAttestationEngine] and a [LegacySoftwareAttestationEngine].
         */
        enableSoftwareAttestation: Boolean = false,

        /**
         * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
         */
        httpProxy: String? = null,
    ) : this(
        listOf(singleApp),
        androidVersion = androidVersion,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareAttestationTrustAnchors = hardwareAttestationTrustAnchors,
        softwareAttestationTrustAnchors = softwareAttestationTrustAnchors,
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableNougatAttestation = enableNougatAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        httpProxy = httpProxy
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
         * **BEWARE** that this switch is utterly useless if [LegacyNougatHybridAttestationEngine] of [LegacySoftwareAttestationEngine] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
         * **BEWARE** that this switch is utterly useless if [LegacyNougatHybridAttestationEngine] of [LegacySoftwareAttestationEngine] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = false,


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
        attestationStatementValiditySeconds: Long? = 5 * 60,

        /**
         * Entirely disable creation of a [LegacyHardwareAttestationEngine]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */

        disableHardwareAttestation: Boolean = false,

        /**
         * Enables hybrid attestation. A [LegacyNougatHybridAttestationEngine] can only be instantiated if this flag is set to true.
         * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
         * devices only support hardware-backed key attestation, but provide no indication about the OS state.
         * Hence, app-attestation cannot be trusted, but key attestation still can.
         */
        enableNougatAttestation: Boolean = false,

        /**
         * Enables software attestation. A [LegacySoftwareAttestationEngine] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [LegacyHardwareAttestationEngine] and a [LegacySoftwareAttestationEngine].
         */
        enableSoftwareAttestation: Boolean = false,


        /**
         * Manually specify the trust anchors for HW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchor is accessible through [GOOGLE_ROOT_CA_PUB_KEY].
         */
        hardwareAttestationRootKeys: Set<ByteArray> = DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.encoded }.toSet(),

        /**
         * Manually specify the trust anchor for SW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are [GOOGLE_SOFTWARE_EC_ROOT], [GOOGLE_SOFTWARE_RSA_ROOT]
         */
        softwareAttestationRootKeys: Set<ByteArray> = DEFAULT_SOFTWARE_TRUST_ANCHORS.map { it.encoded }.toSet(),

        /**
         * List of applications, which can be attested
         */
        apps: List<AppData>,

        /**
         * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
         */
        httpProxy: String? = null,
    ) : this(
        applications = apps,
        androidVersion = version,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareAttestationTrustAnchors = hardwareAttestationRootKeys.map { it.parsePublicKey() }.toSet(),
        softwareAttestationTrustAnchors = softwareAttestationRootKeys.map { it.parsePublicKey() }.toSet(),
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableNougatAttestation = enableNougatAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        httpProxy = httpProxy,
    )

    /**
     * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
     */
    val osPatchLevel: Int? = patchLevel?.asSingleInt

    /**
     * Specifies a to-be attested app
     *
     * @param packageName Android app package name (e.g. `at.asitplus.demo`)
     * @param signatureDigests SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing
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
        val signatureDigests: List<@Serializable(with = ByteArrayBase64UrlSerializer::class) ByteArray>,

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
        internal val patchLevelOverride: PatchLevel? = null,

        /**
         * optional parameter. If set, all globally configured trust anchors are discarded and only the trust anchors specified here are used to attest this app.
         */
        val trustAnchorOverrides: Set<@Serializable(with = PubKeyBasePemSerializer::class) PublicKey>? = null,

        ) {
        init {
            if (signatureDigests.isEmpty()) throw object :
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
        class Builder(private val packageName: String, private val signatureDigests: List<ByteArray>) {

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

            private var trustAnchorOverrides: Set<PublicKey>? = null

            /**
             * @see AppData.appVersion
             */
            fun appVersion(version: Int) = apply { appVersion = version }

            /**
             * @see AppData.androidVersionOverride
             */
            fun overrideAndroidVersion(version: Int) = apply { androidVersionOverride = version }

            /**
             * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
             */
            fun overridePatchLevel(level: PatchLevel) = apply { patchLevelOverride = level }

            /**
             * optional parameter. If set, all globally configured trust anchors are discarded and only the trust anchors specified here are used to attest this app.
             */
            fun overrideTrustAnchors(trustAnchors: Set<PublicKey>) = apply { trustAnchorOverrides = trustAnchors }

            fun build() =
                AppData(
                    packageName,
                    signatureDigests,
                    appVersion,
                    androidVersionOverride,
                    patchLevelOverride,
                    trustAnchorOverrides
                )
        }

        override fun toString(): String {
            return "AppData(" +
                    "packageName='$packageName', " +
                    "signatureDigests=${signatureDigests.joinToString { it.encodeBase64() }}, " +
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

            if (signatureDigests.size != other.signatureDigests.size) return false
            signatureDigests.forEachIndexed { index, byteArray ->
                if (!other.signatureDigests[index].contentEquals(
                        byteArray
                    )
                ) return false
            }

            if (patchLevelOverride != other.patchLevelOverride) return false

            return true
        }

        override fun hashCode(): Int {
            var result = appVersion ?: 0
            result = 31 * result + (androidVersionOverride ?: 0)
            result = 31 * result + (osPatchLevel ?: 0)
            result = 31 * result + packageName.hashCode()
            result = 31 * result + signatureDigests.hashCode()
            result = 31 * result + (patchLevelOverride?.hashCode() ?: 0)
            return result
        }

    }

    init {
        if (hardwareAttestationTrustAnchors.isEmpty() && softwareAttestationTrustAnchors.isEmpty())
            throw object : AndroidAttestationException("No trust anchors configured", null) {}

        if (applications.isEmpty()) throw object : AndroidAttestationException("No apps configured", null) {}
        if (disableHardwareAttestation && !enableSoftwareAttestation && !enableNougatAttestation)
            throw object : AndroidAttestationException(
                "Neither hardware, nor hybrid, nor software attestation enabled", null
            ) {}
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
        private var ignoreLeafValidity: Boolean = false
        private var hardwareAttestationTrustAnchors = mutableSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS)
        private var softwareAttestationTrustAnchors = mutableSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS)
        private var verificationSecondsOffset = 0L
        private var attestationStatementValiditySeconds: Long? = 5 * 60
        private var disableHwAttestation: Boolean = false
        private var enableSwAttestation: Boolean = false
        private var enableNougatAttestation: Boolean = false
        private var httpProxy: String? = null

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
         */
        fun allowBootloaderUnlock() = apply { bootloaderUnlockAllowed = true }

        /**
         * @see AndroidAttestationConfiguration.requireRollbackResistance
         */
        fun requireRollbackResistance() = apply { rollbackResitanceRequired = true }

        /**
         * @see AndroidAttestationConfiguration.ignoreLeafValidity
         */
        fun ingoreLeafValidity() = apply { ignoreLeafValidity = true }

        /**
         * @see AndroidAttestationConfiguration.hardwareAttestationTrustAnchors
         */
        fun hardwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { hardwareAttestationTrustAnchors.apply { clear(); addAll(anchors) } }

        /**
         * adds a single hardware attestation trust anchor
         * @see AndroidAttestationConfiguration.hardwareAttestationTrustAnchors
         */
        fun addHardwareAttestationTrustAnchor(anchor: PublicKey) = apply { hardwareAttestationTrustAnchors += anchor }

        /**
         * @see AndroidAttestationConfiguration.softwareAttestationTrustAnchors
         */
        fun softwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { softwareAttestationTrustAnchors.apply { clear(); addAll(anchors) } }

        /**
         * adds a single software attestation trust anchor
         * @see AndroidAttestationConfiguration.softwareAttestationTrustAnchors
         */
        fun addSoftwareAttestationTrustAnchor(anchor: PublicKey) = apply { softwareAttestationTrustAnchors += anchor }

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
         * @see AndroidAttestationConfiguration.enableNougatAttestation
         */
        fun enableNougatAttestation() = apply { enableNougatAttestation = true }

        /**
         * @see AndroidAttestationConfiguration.httpProxy
         */
        fun httpProxy(url: String) = apply { httpProxy = url }

        fun build() = AndroidAttestationConfiguration(
            applications = applications,
            androidVersion = androidVersion,
            patchLevel = patchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = bootloaderUnlockAllowed,
            requireRollbackResistance = rollbackResitanceRequired,
            ignoreLeafValidity = ignoreLeafValidity,
            hardwareAttestationTrustAnchors = hardwareAttestationTrustAnchors,
            softwareAttestationTrustAnchors = softwareAttestationTrustAnchors,
            verificationSecondsOffset = verificationSecondsOffset,
            attestationStatementValiditySeconds = attestationStatementValiditySeconds,
            disableHardwareAttestation = disableHwAttestation,
            enableSoftwareAttestation = enableSwAttestation,
            enableNougatAttestation = enableNougatAttestation,
            httpProxy = httpProxy,
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
                "hardwareAttestationTrustAnchors=${hardwareAttestationTrustAnchors.joinToString { it.encoded.encodeBase64() }}, " +
                "softwareAttestationTrustAnchors=${softwareAttestationTrustAnchors.joinToString { it.encoded.encodeBase64() }}, " +
                "verificationSecondsOffset=$verificationSecondsOffset, " +
                "attestationStatementValiditySeconds=$attestationStatementValiditySeconds, " +
                "disableHardwareAttestation=$disableHardwareAttestation, " +
                "enableNougatAttestation=$enableNougatAttestation, " +
                "enableSoftwareAttestation=$enableSoftwareAttestation, " +
                "httpProxy=$httpProxy, " +
                "osPatchLevel=$osPatchLevel" +
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
        if (enableNougatAttestation != other.enableNougatAttestation) return false
        if (enableSoftwareAttestation != other.enableSoftwareAttestation) return false
        if (osPatchLevel != other.osPatchLevel) return false
        if (applications != other.applications) return false
        if (patchLevel != other.patchLevel) return false

        if (hardwareAttestationTrustAnchors.size != other.hardwareAttestationTrustAnchors.size) return false
        hardwareAttestationTrustAnchors.forEachIndexed { index, publicKey -> if (!publicKey.encoded.contentEquals(other.hardwareAttestationTrustAnchors.toList()[index].encoded)) return false }

        if (softwareAttestationTrustAnchors.size != other.softwareAttestationTrustAnchors.size) return false
        softwareAttestationTrustAnchors.forEachIndexed { index, publicKey -> if (!publicKey.encoded.contentEquals(other.softwareAttestationTrustAnchors.toList()[index].encoded)) return false }

        if (httpProxy != other.httpProxy) return false

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
        result = 31 * result + enableNougatAttestation.hashCode()
        result = 31 * result + enableSoftwareAttestation.hashCode()
        result = 31 * result + (osPatchLevel ?: 0)
        result = 31 * result + applications.hashCode()
        result = 31 * result + (patchLevel?.hashCode() ?: 0)
        result = 31 * result + hardwareAttestationTrustAnchors.hashCode()
        result = 31 * result + softwareAttestationTrustAnchors.hashCode()
        result = 31 * result + (httpProxy?.hashCode() ?: 0)
        return result
    }


    /**
     * Creates a legacy Android attestation engine matching [level]
     * @throws AndroidAttestationException in case the security level clashes with the config (i.e. [level]` = `[AttestationSecurityLevel.HARDWARE] but [disableHardwareAttestation]` = true` )
     */
    @Throws(AndroidAttestationException::class)
    fun legacyEngineForLevel(level: AttestationSecurityLevel): LegacyAttestationEngine =
        when (level) {
            AttestationSecurityLevel.HARDWARE -> LegacyHardwareAttestationEngine(this)
            AttestationSecurityLevel.NOUGAT -> LegacyNougatHybridAttestationEngine(this)
            AttestationSecurityLevel.SOFTWARE -> LegacySoftwareAttestationEngine(this)
        }

}


enum class AttestationSecurityLevel {
    HARDWARE,
    NOUGAT,
    SOFTWARE
}

private fun ByteArray.parsePublicKey() =
    catchingUnwrapped {
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(this))
    }.getOrElse {
        catchingUnwrapped {
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(this))
        }.getOrElse {
            throw object : AndroidAttestationException("Not a valid public key: ${this.encodeBase64()}", null) {}
        }
    }