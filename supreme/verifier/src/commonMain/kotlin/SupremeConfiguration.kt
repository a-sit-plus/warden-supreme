package at.asitplus.attestation.supreme

import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import net.mamoe.yamlkt.Yaml
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Integrated attestation configuration for the Supreme attestation verifier
 *
 * This configuration deals with two aspects of integrated attestation:
 * - Configuring attestation policies for Android and iOS.
 * - Defining object identifiers and key constraints for fully integrated attestation.
 *
 * To add custom Android revocation checkers, see [AndroidRevocationList.loaderRegistry].
 * To add custom time sources / clocks, see [SupremeConfiguration.Clock.registry]
 *
 *
 * @see AttestationVerifier for more details on the semantics od OIDs and [KeyConstraints]
 *
 * @property android Android-specific attestation configuration. For full details, see [AndroidAttestationConfiguration]
 * @property ios iOS-specific attestation configuration. For full details, see [IosAttestationConfiguration]
 * @property verificationTimeOffset The time offset used during attestation verification.
 * @property attestationProofOID Object identifier for the attestation proof.
 * @property genericDeviceNameOID Optional object identifier for the generic device name.
 * @property defaultKeyConstraints Configuration for default key constraints, such as supported cryptographic operations.
 */
@ExposedCopyVisibility
@Serializable
data class SupremeConfiguration
@Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
private constructor(
    val ios: IosAttestationConfiguration?,
    val android: AndroidAttestationConfiguration?,
    val clock: SupremeConfiguration.Clock = SupremeConfiguration.Clock.System,
    val verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
    val defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
) : AttestationConfiguration {

    @Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
    constructor(
        android: AndroidAttestationConfiguration,
        ios: IosAttestationConfiguration,
        clock: SupremeConfiguration.Clock = SupremeConfiguration.Clock.System,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        ios,
        android,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
    )

    /**
     * iOS-Only configuration
     */
    @Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
    constructor(
        ios: IosAttestationConfiguration,
        clock: SupremeConfiguration.Clock = SupremeConfiguration.Clock.System,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        ios,
        null,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
    )

    /**
     * Android-Only configuration
     */
    @Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
    constructor(
        android: AndroidAttestationConfiguration,
        clock: SupremeConfiguration.Clock = SupremeConfiguration.Clock.System,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        null,
        android,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
    )

    init {
        require(android != null || ios != null) { "At least one attestation configuration (iOS or Android) must be provided" }
    }

    override fun toJsonString(): String = json.encodeToString(this)

    override fun toYamlString(): String = yaml.encodeToString(this)

    override fun toJsonElement(): JsonObject = json.encodeToJsonElement(this).jsonObject

    companion object : AttestationConfiguration.Reader<SupremeConfiguration> {

        private val yaml by lazy {
            Yaml {
                serializersModule =
                    AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e } + Clock.registry.modules.reduce { acc, e -> acc + e }
            }
        }

        private val json by lazy {
            Json {
                encodeDefaults = true
                ignoreUnknownKeys = true
                prettyPrint = true
                serializersModule =
                    AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e } + Clock.registry.modules.reduce { acc, e -> acc + e }
                classDiscriminator = "type"
            }
        }

        override fun fromJsonString(jsonRepresentation: String): SupremeConfiguration =
            json.decodeFromString(jsonRepresentation)

        override fun fromYamlString(yamlRepresentation: String): SupremeConfiguration =
            yaml.decodeFromString(yamlRepresentation)

        override fun fromJsonObject(jsonRepresentation: JsonElement): SupremeConfiguration =
            json.decodeFromJsonElement(jsonRepresentation)

    }

    /**
     * Configures the time source of a [SupremeConfiguration]
     */
    interface Clock {

        /**
         * Provides a reference to the current time source being used.
         *
         * Multiple calls are expected to return the same source.
         */
        val timeSource: kotlin.time.Clock

        @Serializable
        @SerialName("system")
        class SystemClock : Clock {
            override val timeSource get() = kotlin.time.Clock.System
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is SystemClock) return false

                if (timeSource != other.timeSource) return false

                return true
            }

            override fun hashCode(): Int {
                return timeSource.hashCode()
            }
            override fun toString(): String = "System"
        }

        companion object {

            val System = SystemClock()
            /**
             * Use to register custom [SupremeConfiguration.Clock]s, if you need custom externalised clock configuration.
             * Must be called only once before ever using the registered clock configs.
             *
             * @See SerializerRegistry
             */
            val registry = SerializerRegistry(SupremeConfiguration.Clock::class)

            init {
                registry.register(SupremeConfiguration.Clock.SystemClock::class)
            }
        }
    }
}

/**
 * Convenience extension to create a [Makoto] instance from [configuration]
 */
@Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
operator fun Makoto.Companion.invoke(configuration: SupremeConfiguration): Makoto =
    if (configuration.ios == null) Makoto(
        androidAttestationConfiguration = configuration.android!!,
        clock = configuration.clock.timeSource,
        verificationTimeOffset = configuration.verificationTimeOffset
    )
    else if (configuration.android == null) Makoto(
        iosAttestationConfiguration = configuration.ios!!,
        clock = configuration.clock.timeSource,
        verificationTimeOffset = configuration.verificationTimeOffset
    )
    else Makoto(
        androidAttestationConfiguration = configuration.android,
        iosAttestationConfiguration = configuration.ios,
        clock = configuration.clock.timeSource,
        verificationTimeOffset = configuration.verificationTimeOffset
    )
