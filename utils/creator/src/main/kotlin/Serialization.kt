@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.attestation.creator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlin.time.Instant

/**
 * JSON codec for [CreatorConfig].
 *
 * Unknown keys are rejected: a config file that this tool does not fully understand would silently
 * produce a different attestation than intended.
 */
internal val CreatorJson = Json {
    encodeDefaults = true
    ignoreUnknownKeys = false
    prettyPrint = true
}

/**
 * ### Serializers
 *
 * The creator has exactly one domain model: the parser types from `supreme-common`. Nothing below
 * mirrors, wraps, or re-interprets them — these serializers only give those types a JSON form.
 * The ASN.1 encoding is authoritative in every case, so a config file round-trips to the very same
 * bytes that go into a certificate, including deliberately malformed ones.
 */

/** ISO-8601, because a config file is read by humans. */
internal object InstantAsIso8601 : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("creator.Instant", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Instant) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): Instant = Instant.parse(decoder.decodeString())
}

internal object ByteArrayAsHex : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("creator.HexBytes", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.toHexString())
    override fun deserialize(decoder: Decoder): ByteArray = decoder.decodeString().hexToByteArray()
}

/** A complete DER element as hex, tag and length included. */
internal object Asn1ElementAsHex : KSerializer<Asn1Element> {
    override val descriptor = PrimitiveSerialDescriptor("creator.HexDer", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Asn1Element) = encoder.encodeString(value.derEncoded.toHexString())
    override fun deserialize(decoder: Decoder): Asn1Element = Asn1Element.parse(decoder.decodeString().hexToByteArray())
}

internal object SecurityLevelAsName : KSerializer<SecurityLevel> {
    private val names = mapOf(
        SecurityLevel.SOFTWARE to "SOFTWARE",
        SecurityLevel.TRUSTED_ENVIRONMENT to "TEE",
        SecurityLevel.STRONGBOX to "STRONGBOX",
    )

    override val descriptor = PrimitiveSerialDescriptor("creator.SecurityLevel", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: SecurityLevel) = encoder.encodeString(names.getValue(value))
    override fun deserialize(decoder: Decoder): SecurityLevel = decoder.decodeString().let { name ->
        names.entries.firstOrNull { it.value == name }?.key
            ?: throw IllegalArgumentException("Unknown security level: $name (expected one of ${names.values})")
    }
}

/**
 * An authorization list as the list of its explicitly tagged properties, each in complete DER.
 *
 * This is the same representation the parser itself is built on ([AuthorizationList.elements]), which
 * makes normal properties and hand-crafted (`mangle`d) ones indistinguishable here — as they should be:
 * both are just properties of the sequence, and both survive the round-trip byte-for-byte.
 */
internal object AuthorizationListAsProperties : KSerializer<AuthorizationList> {
    private val delegate = ListSerializer(Asn1ElementAsHex)
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: AuthorizationList) =
        delegate.serialize(encoder, value.encodeToTlv().children)

    override fun deserialize(decoder: Decoder): AuthorizationList =
        AuthorizationList.decodeFromTlv(Asn1.Sequence { delegate.deserialize(decoder).forEach { +it } })
}

/**
 * [AttestationKeyDescription] in schema shape.
 *
 * [Surrogate] is serialization plumbing, not a second model: it carries no logic and no state of its
 * own, every one of its fields is a field of the parser type, and its defaults are read off
 * [DefaultKeyDescription] instead of being restated.
 */
internal object KeyDescriptionAsSchema : KSerializer<AttestationKeyDescription> {
    @Serializable
    @SerialName("AttestationKeyDescription")
    private class Surrogate(
        val attestationVersion: Int = DefaultKeyDescription.attestationVersion,
        val attestationSecurityLevel: @Serializable(SecurityLevelAsName::class) SecurityLevel =
            DefaultKeyDescription.attestationSecurityLevel,
        val keyMintVersion: Int = DefaultKeyDescription.keyMintVersion,
        val keyMintSecurityLevel: @Serializable(SecurityLevelAsName::class) SecurityLevel =
            DefaultKeyDescription.keyMintSecurityLevel,
        val attestationChallenge: @Serializable(ByteArrayAsHex::class) ByteArray =
            DefaultKeyDescription.attestationChallenge,
        val uniqueId: @Serializable(ByteArrayAsHex::class) ByteArray = DefaultKeyDescription.uniqueId,
        val softwareEnforced: @Serializable(AuthorizationListAsProperties::class) AuthorizationList =
            DefaultKeyDescription.softwareEnforced,
        val hardwareEnforced: @Serializable(AuthorizationListAsProperties::class) AuthorizationList =
            DefaultKeyDescription.hardwareEnforced,
    )

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: AttestationKeyDescription) = Surrogate.serializer().serialize(
        encoder, with(value) {
            Surrogate(
                attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel,
                attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced
            )
        }
    )

    override fun deserialize(decoder: Decoder): AttestationKeyDescription =
        with(Surrogate.serializer().deserialize(decoder)) {
            AttestationKeyDescription(
                attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel,
                attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced
            )
        }
}
