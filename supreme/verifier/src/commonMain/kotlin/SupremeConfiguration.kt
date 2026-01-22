package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList.Companion.configurationSerializerModules
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import net.mamoe.yamlkt.Yaml
import kotlin.time.Duration

/**
 * Integrated attestation configuration for the Supreme attestation verifier
 *
 * This configuration deals with two aspects of integrated attestation:
 * - Configuring attestation policies for Android and iOS.
 * - Defining object identifiers and key constraints for fully integrated attestation.
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
@Serializable
data class SupremeConfiguration private constructor(
    val ios: IosAttestationConfiguration?,
    val android: AndroidAttestationConfiguration?,
    val verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
    val defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
) : AttestationConfiguration {


    constructor(
        android: AndroidAttestationConfiguration,
        ios: IosAttestationConfiguration,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        ios,
        android,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
    )

    /**
     * iOS-Only configuration
     */
    constructor(
        ios: IosAttestationConfiguration,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        ios,
        null,
        verificationTimeOffset,
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
    )
    /**
     * Android-Only configuration
     */
    constructor(
        android: AndroidAttestationConfiguration,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    ) : this(
        null,
        android,
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
                serializersModule = configurationSerializerModules.reduce { acc, e -> acc + e }
            }
        }

        private val json by lazy {
            Json {
                encodeDefaults = true
                ignoreUnknownKeys = true
                prettyPrint = true
                serializersModule = configurationSerializerModules.reduce { acc, e -> acc + e }
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
}