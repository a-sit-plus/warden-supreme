package at.asitplus.attestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import net.swiftzer.semver.SemVer

@Deprecated("Legacy name", replaceWith = ReplaceWith("IosAttestationConfiguration"))
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
     * Optional parameter. If present the iOS version of the attested app must be greater or equal to this parameter
     * Uses [SemVer](https://semver.org/) syntax. Can be overridden vor individual apps.
     *
     * @see AppData.iosVersionOverride
     */
    val iosVersion: OsVersions? = null,

    /**
     * The maximum age an attestation statement is considered valid.
     */
    val attestationStatementValiditySeconds: Long = 5 * 60

) {


    @JvmOverloads
    constructor(
        singleApp: AppData,
        iosVersion: OsVersions? = null,
        attestationStatementValiditySeconds: Long = 5 * 60
    ) : this(listOf(singleApp), iosVersion, attestationStatementValiditySeconds)

    init {
        if (applications.isEmpty())
            throw AttestationException.Configuration(Platform.IOS, "No apps configured", IllegalArgumentException())
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

            /**
             * @see AppData.sandbox
             */
            fun sandbox(sandbox: Boolean) = apply { this.sandbox = sandbox }

            /**
             * @see AppData.iosVersionOverride
             */
            fun overrideIosVersion(version: OsVersions) = apply { iosVersionOverride = version }

            fun build() = AppData(teamIdentifier, bundleIdentifier, sandbox, iosVersionOverride)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IosAttestationConfiguration) return false

        if (attestationStatementValiditySeconds != other.attestationStatementValiditySeconds) return false
        if (applications != other.applications) return false
        if (iosVersion != other.iosVersion) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestationStatementValiditySeconds
        result = 31 * result + applications.hashCode()
        result = 31 * result + (iosVersion?.hashCode() ?: 0)
        return result.toInt()
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

