package at.asitplus.attestation

import at.asitplus.attestation.IosAttestationConfiguration.Companion.DEFAULT_VALIDITY_SECONDS
import at.asitplus.attestation.IosAttestationConfiguration.Companion.fromJsonObject
import at.asitplus.attestation.IosAttestationConfiguration.Companion.fromJsonString
import at.asitplus.attestation.android.TrustedRoot
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import net.mamoe.yamlkt.Yaml
import net.swiftzer.semver.SemVer
import kotlin.time.toKotlinDuration

//TODO remove in 1.1
@Deprecated("Legacy name, will be removed in 1.1", replaceWith = ReplaceWith("IosAttestationConfiguration"))
typealias IOSAttestationConfiguration = IosAttestationConfiguration

/**
 * Configuration class for Apple App Attestation
 */
@Serializable
data class IosAttestationConfiguration @JvmOverloads constructor(

    /**
     * List of applications that can be attested
     */
    val applications: List<AppData>,

    /**
     * Optional parameter. If present, the iOS version of the attested app must be greater or equal to this parameter
     * Uses [SemVer](https://semver.org/) syntax. Can be overridden for individual apps.
     *
     * @see AppData.iosVersionOverride
     */
    val iosVersion: OsVersions? = null,

    /**
     * The maximum age an attestation statement is considered valid. Defaults to [DEFAULT_VALIDITY_SECONDS]
     */
    val attestationStatementValiditySeconds: Long = DEFAULT_VALIDITY_SECONDS,

    /**
     * Manually specify the trust anchors.
     * Apple's trust anchors come in pairs: a [TrustedRootPair.attestationRoot] and a [TrustedRootPair.receiptRoot].
     * Defaults to the Apples trust anchors available in [APPLE_DEFAULT_TRUSTED_ROOTS].
     * Overriding this set is useful for automated end-to-end tests, for example.
     * Note that currently only Certificates are supported as trust anchors, no raw public keys
     */
    val trustedRoots: Set<TrustedRootPair> = APPLE_DEFAULT_TRUSTED_ROOTS,
) : AttestationConfiguration {


    @JvmOverloads
    constructor(
        singleApp: AppData,
        iosVersion: OsVersions? = null,
        attestationStatementValiditySeconds: Long = (ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE.toKotlinDuration() + Makoto.DEFAULT_TIME_OFFSET).inWholeSeconds,
        trustedRoots: Set<TrustedRootPair>
        = APPLE_DEFAULT_TRUSTED_ROOTS,
    ) : this(listOf(singleApp), iosVersion, attestationStatementValiditySeconds, trustedRoots)

    init {
        if (trustedRoots.isEmpty())
            throw AttestationException.Configuration(
                Platform.IOS,
                "No trust anchors configured",
                IllegalArgumentException()
            )


        if (applications.isEmpty())
            throw AttestationException.Configuration(Platform.IOS, "No apps configured", IllegalArgumentException())

        if (attestationStatementValiditySeconds < 0)
            throw AttestationException.Configuration(
                Platform.IOS,
                "Attestation statement validity must not be negative",
                IllegalArgumentException()
            )
    }

    /**
     * Container class for iOS versions. Necessary, iOS versions used to always be encoded into attestation statements using
     * [SemVer](https://semver.org/) syntax. Newer iPhones, however, use a hex string representation of the build number instead.
     * Since it makes rarely sense to only check for SemVer not for a hex-encoded build number (i.e only accept older iPhones),
     * encapsulating both variants into a dedicated type ensures that either both or neither are set.
     */
    @Serializable
    data class OsVersions(
        /**
         * [SemVer](https://semver.org/)-formatted iOS version number.
         * This property is a simple string, because it plays nicely when externalising configuration to files, since
         * it doesn't require a custom deserializer/decoder.
         */
        private val semVer: String,

        /**
         * String representation of an iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
         * @see BuildNumber
         */
        private val buildNumber: String,

        ) : Comparable<Any> {

        /**
         * Parsed and normalised iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
         * @see BuildNumber
         */
        @Transient
        val normalisedBuildNumber: BuildNumber = runCatching { BuildNumber(buildNumber) }.getOrElse { ex ->
            throw AttestationException.Configuration(
                Platform.IOS,
                "Illegal iOS build number $buildNumber",
                ex
            )
        }

        /**
         * [SemVer](https://semver.org/)-formatted iOS version number.
         */
        @Transient
        val semVerParsed: SemVer =
            runCatching { SemVer.parse(semVer) }.getOrElse { ex ->
                throw AttestationException.Configuration(
                    Platform.IOS,
                    "Illegal iOS version number $semVer",
                    ex
                )
            }

        override fun toString(): String =
            "iOS Versions (semVer=$semVerParsed, buildNumber: $normalisedBuildNumber)"

        override fun compareTo(other: Any): Int {
            return when (other) {
                is BuildNumber -> normalisedBuildNumber.compareTo(other)
                is SemVer -> semVerParsed.compareTo(other)
                is Pair<*, *> -> {
                    if ((other.first is SemVer || other.first is SemVer?) && (other.second is BuildNumber || other.second is BuildNumber?)) {
                        other.first?.let { return semVerParsed.compareTo(it as SemVer) }
                            ?: other.second?.let { normalisedBuildNumber.compareTo(it as BuildNumber) }
                            ?: throw UnsupportedOperationException("No Parsed iOS Version present.")
                    } else throw UnsupportedOperationException("Cannot compare OsVersions to ${other::class.simpleName}")
                }

                else -> throw UnsupportedOperationException("Cannot compare OsVersions to ${other::class.simpleName}")
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is OsVersions) return false

            if (semVer != other.semVer) return false
            if (buildNumber != other.buildNumber) return false

            return true
        }

        override fun hashCode(): Int {
            var result = semVer.hashCode()
            result = 31 * result + buildNumber.hashCode()
            return result
        }
    }


    /**
     * Specifies a to-be attested app
     */
    @Serializable
    data class AppData @JvmOverloads constructor(
        /**
         * Nomen est omen
         */
        val teamIdentifier: String,

        /**
         * Nomen est omen
         */
        val bundleIdentifier: String,

        /**
         * Specifies whether the to-be-attested app targets a production or sandbox environment
         */
        val sandbox: Boolean = false,

        /**
         * Optional parameter. If present, overrides the globally configured iOS version for this app.
         */
        val iosVersionOverride: OsVersions? = null,

        /**
         * Optional parameter. IF present, takes precedence over the globally configured trust anchors.
         */
        val trustedRootOverrides: Set<TrustedRootPair>? = null,

        ) {

        /**
         * Builder for more Java-friendliness
         * @param teamIdentifier nomen est omen
         * @param bundleIdentifier nomen est omen
         */
        @Suppress("UNUSED")
        class Builder(private val teamIdentifier: String, private val bundleIdentifier: String) {
            private var sandbox = false
            private var iosVersionOverride: OsVersions? = null
            private var trustedRootOverrides: Set<TrustedRootPair>? =
                null

            /**
             * @see AppData.sandbox
             */
            fun sandbox(sandbox: Boolean) = apply { this.sandbox = sandbox }

            /**
             * @see AppData.iosVersionOverride
             */
            fun iosVersionOverride(version: OsVersions) = apply { iosVersionOverride = version }

            /**
             * @see AppData.trustedRootOverrides
             */
            fun trustedRootOverrides(trustAnchors: Set<TrustedRootPair>) =
                apply { trustedRootOverrides = trustAnchors }

            fun build() = AppData(teamIdentifier, bundleIdentifier, sandbox, iosVersionOverride, trustedRootOverrides)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AppData) return false

            if (sandbox != other.sandbox) return false
            if (teamIdentifier != other.teamIdentifier) return false
            if (bundleIdentifier != other.bundleIdentifier) return false
            if (iosVersionOverride != other.iosVersionOverride) return false
            if (trustedRootOverrides?.map { it.toString() } != other.trustedRootOverrides?.map { it.toString() }) return false

            return true
        }

        override fun hashCode(): Int {
            var result = sandbox.hashCode()
            result = 31 * result + teamIdentifier.hashCode()
            result = 31 * result + bundleIdentifier.hashCode()
            result = 31 * result + (iosVersionOverride?.hashCode() ?: 0)
            result = 31 * result + (trustedRootOverrides?.hashCode() ?: 0)
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IosAttestationConfiguration) return false

        if (attestationStatementValiditySeconds != other.attestationStatementValiditySeconds) return false
        if (applications != other.applications) return false
        if (iosVersion != other.iosVersion) return false
        if (trustedRoots.map { it.toString() } != other.trustedRoots.map { it.toString() }) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestationStatementValiditySeconds
        result = 31 * result + applications.hashCode()
        result = 31 * result + (iosVersion?.hashCode() ?: 0)
        return result.toInt()
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

    companion object : AttestationConfiguration.Reader<IosAttestationConfiguration> {

        private val yaml by lazy {
            Yaml {
            }
        }

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        override fun fromJsonString(jsonRepresentation: String): IosAttestationConfiguration =
            jsonDebug.decodeFromString<IosAttestationConfiguration>(jsonRepresentation)

        /**
         * Loads the config from its canonical form (YAML), as produced by [toJsonString].
         */
        override fun fromYamlString(yamlRepresentation: String): IosAttestationConfiguration =
            yaml.decodeFromString<IosAttestationConfiguration>(yamlRepresentation)

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonElement].
         */
        override fun fromJsonObject(jsonRepresentation: JsonElement): IosAttestationConfiguration =
            jsonDebug.decodeFromJsonElement<IosAttestationConfiguration>(jsonRepresentation)

        /**[ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE] + [Makoto.DEFAULT_TIME_OFFSET]**/
        val DEFAULT_VALIDITY_SECONDS: Long =
            (ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE.toKotlinDuration() + Makoto.DEFAULT_TIME_OFFSET).inWholeSeconds
    }
}

typealias ParsedVersions = Pair<SemVer?, BuildNumber?>

/**
 * iOS build number. As per [TidBITS.com](https://tidbits.com/2020/07/08/how-to-decode-apple-version-and-build-numbers/):
 *
 * An Apple build number also has three parts:
 *
 * *  Major version: Within Apple, the major version is called the build train.
 * *  Minor version: For iOS and its descendants, the minor version tracks with the minor release; for macOS, it tracks with patch releases.
 * *  Daily build version: The daily build indicates how many times Apple has built the source code for the release since the previous public release.
 * *  Optional mastering counter; only relevant for internal builds an betas
 *
 * While this last bit about the daily build number is phrased somewhat fuzzy, it really is a strictly increasing decimal number.
 */
class BuildNumber private constructor(
    val buildTrain: UInt,
    val minorVersion: String,
    val buildVer: UInt,
    val masteringCounter: String? = null
) : Comparable<BuildNumber> {


    constructor(buildNumber: String) : this(parseBuildNumber(buildNumber))

    private constructor(boxed: Pair<Triple<UInt, String, UInt>, String?>) : this(
        boxed.first.first,
        boxed.first.second,
        boxed.first.third,
        boxed.second
    )


    /**
     * Integer representation of the build number. Converts [buildTrain] into a hex number, concatenates it with [minorVersion] radix-36-parsed
     * to a hex number and concatenates it with an end-padded hex-representation of [buildVer].
     * This results in a [UInt] whose MSBs are always set for correct and straight-forward comparison of build numbers.
     * The implementation is inefficient but comprehensible.
     */
    val semVerRepresentation: SemVer = SemVer(
        buildTrain.toInt(),
        minor = minorVersion.toInt(36),
        patch = buildVer.toInt(),
        preRelease = masteringCounter
    )

    override fun compareTo(other: BuildNumber): Int = semVerRepresentation.compareTo(other.semVerRepresentation)

    override fun toString() = "$buildTrain$minorVersion$buildVer ($semVerRepresentation)"

    companion object {
        private fun parseBuildNumber(stringRepresentation: String): Pair<Triple<UInt, String, UInt>, String?> {
            val buildTrain = stringRepresentation.takeWhile { it.isDigit() }

            val minorVersion = stringRepresentation.substring(buildTrain.length).takeWhile { it.isLetter() }
            val masteringCounter = stringRepresentation.takeLastWhile { it.isLetter() }
            val buildVer = stringRepresentation.substring(
                buildTrain.length + minorVersion.length,
                stringRepresentation.length - masteringCounter.length
            ).toUInt(10)

            return Triple(
                buildTrain.toUInt(10),
                minorVersion,
                buildVer
            ) to masteringCounter.let { if (it.isEmpty()) null else it }
        }
    }
}

/**
 * Represents a pair of trusted root entities for Apple's AppAttest ecosystem.
 */
@Serializable
data class TrustedRootPair(val attestationRoot: TrustedRoot, val receiptRoot: TrustedRoot)


/**
 * Represents a default tuple of trusted root certificates specific to Apple's ecosystem.
 *
 * `APPLE_DEFAULT_TRUSTED_ROOTS` pairs two `TrustedRoot.Certificate` instances derived from
 * Apple's built-in trust anchors. These trust anchors correspond to:
 *
 * - The root certificate used for Apple App Attest (`APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR`).
 * - The root certificate used for Apple receipt validation (`APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR`).
 *
 */
val APPLE_DEFAULT_TRUSTED_ROOTS: Set<TrustedRootPair> = linkedSetOf(
    TrustedRootPair(
        TrustedRoot.Certificate(AttestationValidator.APPLE_APP_ATTEST_ROOT_CA_BUILTIN_TRUST_ANCHOR.trustedCert),
        TrustedRoot.Certificate(ReceiptValidator.APPLE_PUBLIC_ROOT_CA_G3_BUILTIN_TRUST_ANCHOR.trustedCert)
    )
)
