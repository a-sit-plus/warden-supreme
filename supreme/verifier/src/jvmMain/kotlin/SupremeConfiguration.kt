package at.asitplus.attestation.supreme

import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.*
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import net.mamoe.yamlkt.Yaml
import kotlin.time.Duration

/**
 * Integrated attestation configuration for the Supreme attestation verifier
 *
 * This configuration deals with two aspects of integrated attestation:
 * - Configuring attestation policies for Android and iOS.
 * - Defining object identifiers, key constraints, proof authentication, and requested client attributes for fully
 *   integrated attestation.
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
 * @property dataAuthentication Default authentication mode placed in issued challenges. Signature mode proves private-key
 * possession; hash mode binds the TBS CSR contents through the platform attestation nonce without signing it.
 * @property toBeAttestedAttributes Optional ordered client-provided values to request and bind into every issued challenge.
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
    val dataAuthentication: DataAuthentication = DataAuthentication.Signature,
    @Serializable(with = ConfigurationAttestableAttributesSerializer::class)
    val toBeAttestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
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
        dataAuth: DataAuthentication = DataAuthentication.Signature,
        toBeAttestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
    ) : this(
        ios,
        android,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        dataAuth,
        toBeAttestedAttributes
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
        dataAuth: DataAuthentication = DataAuthentication.Signature,
        toBeAttestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
    ) : this(
        ios,
        null,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        dataAuth,
        toBeAttestedAttributes,
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
        dataAuth: DataAuthentication = DataAuthentication.Signature,
        toBeAttestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
    ) : this(
        null,
        android,
        clock,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        dataAuth,
        toBeAttestedAttributes,
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
    @Serializable(with = Clock.Serializer::class)
    interface Clock {

        /**
         * Provides a reference to the current time source being used.
         *
         * Multiple calls are expected to return the same source.
         */
        val timeSource: kotlin.time.Clock

        @Serializable
        @SerialName("system")
        object System : Clock {
            override val timeSource get() = kotlin.time.Clock.System
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is System) return false

                if (timeSource != other.timeSource) return false

                return true
            }

            override fun hashCode(): Int {
                return timeSource.hashCode()
            }

            override fun toString(): String = "System"
        }

        object Serializer : KSerializer<Clock> {
            override val descriptor: SerialDescriptor =
                PrimitiveSerialDescriptor("SupremeConfiguration.Clock", PrimitiveKind.STRING)

            override fun serialize(encoder: Encoder, value: Clock) {
                if (value is System) {
                    encoder.encodeString("system")
                    return
                }
                encoder.encodeSerializableValue(
                    YamlFlatteningPolymorphicSerializer(Clock::class),
                    value
                )
            }

            override fun deserialize(decoder: Decoder): Clock {
                val scalar = catchingUnwrapped { decoder.decodeString() }.getOrNull()
                if (scalar != null) {
                    if (scalar.equals("system", ignoreCase = true)) return System
                    throw SerializationException("Unknown clock value: $scalar")
                }
                return decoder.decodeSerializableValue(YamlFlatteningPolymorphicSerializer(Clock::class))
            }
        }

        companion object {
            /**
             * Use to register custom [SupremeConfiguration.Clock]s, if you need custom externalised clock configuration.
             * Must be called only once before ever using the registered clock configs.
             *
             * @See SerializerRegistry
             */
            val registry = SerializerRegistry(SupremeConfiguration.Clock::class)

            init {
                //NOOP for our process but useful to keep everything neatly tracked
                registry.register(SupremeConfiguration.Clock.System::class)
            }
        }
    }
}

private object ConfigurationAttestableAttributesSerializer :
    KSerializer<AttestationChallenge.CertificationRequestAttributeAttestationDescriptor> {

    override val descriptor: SerialDescriptor = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor.serializer().descriptor
    private val attributesSerializer = ListSerializer(ConfigurationAttestedAttributeSerializer)

    override fun serialize(encoder: Encoder, value: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ObjectIdentifierStringSerializer, value.oid)
            encodeSerializableElement(descriptor, 1, attributesSerializer, value.attributes)
        }
    }

    override fun deserialize(decoder: Decoder): AttestationChallenge.CertificationRequestAttributeAttestationDescriptor =
        decoder.decodeStructure(descriptor) {
            var oid: ObjectIdentifier? = null
            var attributes: List<AttestationChallenge.AttributeAttestationDescriptor>? = null
            while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break
                    0 -> oid = decodeSerializableElement(descriptor, 0, ObjectIdentifierStringSerializer)
                    1 -> attributes = decodeSerializableElement(descriptor, 1, attributesSerializer)
                    else -> throw SerializationException("Unknown toBeAttestedAttributes element index: $index")
                }
            }
            AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
                requireNotNull(oid) { "Missing toBeAttestedAttributes.oid" },
                requireNotNull(attributes) { "Missing toBeAttestedAttributes.attributes" },
            )
        }
}

private object ConfigurationAttestedAttributeSerializer :
    KSerializer<AttestationChallenge.AttributeAttestationDescriptor> {

    override val descriptor: SerialDescriptor = AttestationChallenge.AttributeAttestationDescriptor.serializer().descriptor

    override fun serialize(encoder: Encoder, value: AttestationChallenge.AttributeAttestationDescriptor) {
        encoder.encodeStructure(descriptor) {
            encodeStringElement(descriptor, 0, value.name)
            encodeSerializableElement(descriptor, 1, PrimitiveType.NameSerializer, value.type)
            if (shouldEncodeElementDefault(descriptor, 2) || !value.required) {
                encodeBooleanElement(descriptor, 2, value.required)
            }
        }
    }

    override fun deserialize(decoder: Decoder): AttestationChallenge.AttributeAttestationDescriptor =
        decoder.decodeStructure(descriptor) {
            var name: String? = null
            var type: PrimitiveType? = null
            var required = true
            while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    CompositeDecoder.DECODE_DONE -> break
                    0 -> name = decodeStringElement(descriptor, 0)
                    1 -> type = decodeSerializableElement(descriptor, 1, PrimitiveType.NameSerializer)
                    2 -> required = decodeBooleanElement(descriptor, 2)
                    else -> throw SerializationException("Unknown ToBeAttestedAttribute element index: $index")
                }
            }
            AttestationChallenge.AttributeAttestationDescriptor(
                requireNotNull(name) { "Missing ToBeAttestedAttribute.name" },
                requireNotNull(type) { "Missing ToBeAttestedAttribute.type" },
                required,
            )
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
        iosAttestationConfiguration = configuration.ios,
        clock = configuration.clock.timeSource,
        verificationTimeOffset = configuration.verificationTimeOffset
    )
    else Makoto(
        androidAttestationConfiguration = configuration.android,
        iosAttestationConfiguration = configuration.ios,
        clock = configuration.clock.timeSource,
        verificationTimeOffset = configuration.verificationTimeOffset
    )
