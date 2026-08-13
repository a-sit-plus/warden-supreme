package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.supreme.AttestationChallenge.Companion.CURRENT_VERSION
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.decodeToString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUtf8String
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import kotlinx.datetime.TimeZone
import kotlinx.datetime.serializers.TimeZoneSerializer
import kotlinx.serialization.*
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Represents a challenge for an attestation ceremony, including freshness, key-generation hints, the required
 * [DataAuthentication] mode, and optional client-provided values that must be bound to the attestation.
 *
 * The class provides serialization support for its fields and enforces strict requirements, such as the maximum size of
 * the nonce. It includes both diagnostic and functional properties to support attestation protocols and ensure client
 * compliance with server requirements.
 *
 * @constructor Primary constructor for internal initialization. Throws [IllegalArgumentException] if the [nonce] exceeds
 * the size restriction.
 *
 * @property issuedAt The issuing time of the nonce, used to check for clock synchronization.
 * @property validity Specifies the duration for which the nonce is valid.
 * @property timeZone The optional timezone of the server where the challenge was issued. This is purely diagnostic, since
 * [Instant] used for timestamps is UTC by definition.
 * @property nonce A server-specified unique identifier, bound by a maximum size of 128 bytes.
 * @property attestationEndpoint The URL endpoint where the signed CSR or unsigned TBS CSR containing the attestation
 * proof will be posted.
 * @property proofOID The Object Identifier used for the TBS CSR attribute carrying the attestation statement.
 * @property genericDeviceNameOID Optional OID specifying whether a generic device name should be included in the
 * attestation proof. If set, the device name is included on a best-effort basis.
 * @property version Indicates the wire format version. The default value is set to [CURRENT_VERSION].
 * @property keyConstraints Specifies constraints on keys that can be used during the attestation process.
 * @property toBeAttestedAttributes Optional ordered description of client-provided values that must be encoded into the
 * TBS CSR and authenticated according to [dataAuth].
 * @property dataAuth Selects whether the client signs the TBS CSR or binds it through a digest used as the platform
 * attestation nonce.
 * @property additionalPayload An optional user-defined map for custom payloads. Constraints on serialization apply,
 * where nested maps or primitives are strictly controlled for cross-format consistency.
 * @property transientData Optional runtime-only attachment. Not serialized and excluded from equality/hashing.
 *
 * @throws IllegalArgumentException If the [nonce] exceeds 128 bytes or is shorter than 4 bytes
 */
@OptIn(ExperimentalSerializationApi::class)
@ConsistentCopyVisibility
@Serializable
data class AttestationChallenge
/**
 * @throws IllegalArgumentException in case the [nonce] is larger than 128 bytes
 */
@Throws(IllegalArgumentException::class)
private constructor(
    /**
     * The issuing time of the nonce. Useful to detect clock drifts and exit early.
     * This is not considered sensible information, as clocks must be in sync anyhow.
     */
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,

    /**
     * How long this nonce is considered valid.
     */
    @Serializable(with = DurationWholeSecondsSerializer::class)
    val validity: Duration,
    /**
     * The server timezone. Purely diagnostic, since [Instant] used for [issuedAt] is UTC by definition.
     * Can be omitted if the server does not want to disclose this information
     */
    @Serializable(with = TimeZoneSerializer::class)
    val timeZone: TimeZone? = null,

    /**
     * The nonce chosen by the server. Must be at most 128 bytes long, as
     * [this is the largest nonce size supported by Android](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestationChallenge(byte%5B%5D)).
     */
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val nonce: ByteArray,

    /**
     * The endpoint to post the signed CSR or unsigned TBS CSR containing the attestation proof to.
     */
    val attestationEndpoint: String,

    /**
     * The OID of the TBS CSR attribute used to transfer the attestation statement.
     */
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val proofOID: ObjectIdentifier,

    /**
     * Whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16" with the attestation proof).
     * Setting this to an OID other than `null` will include a device name on a best-effort basis. Defaults to `null` (i.e., no device name will be included).
     */
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val genericDeviceNameOID: ObjectIdentifier? = null,

    /**
     * Indicates the wire format version; needs to default to `null` for the default serializer to handle it correctly. The public constructor sets this to [CURRENT_VERSION].
     */
    val version: Int? = null,

    /**
     * Specifies key constraints for the client
     */
    val keyConstraints: KeyConstraints? = null,

    /**
     * Optional user-defined payload.
     *
     * Must be a nested map structure, where values are [Constrained] (primitives, nested maps, or `null`).
     *
     * Serialization uses a custom, format-agnostic encoding to avoid pitfalls of formats that may omit default scalar
     * values (e.g. `0`, `false`, `""`) on the wire (as in ProtoBuf-style encodings). Each value is encoded as a
     * "typed envelope" that always includes a non-default discriminator, so a missing value can be reconstructed as
     * the correct default, and `null` can be represented without relying on the underlying format's null support.
     */
    @Serializable(with = ConstrainedMapSerializer::class)
    val additionalPayload: Map<String, Constrained>? = null,

    /**
     * Optional runtime-only attachment for application state.
     *
     * This value is **not** part of the wire format:
     * - It is not serialized (`@Transient`), i.e. it will never be sent to clients and will not be reconstructed when a
     *   challenge is deserialized.
     * - It is excluded from [equals] and [hashCode], so it does not affect challenge identity, caching, or replay checks.
     *
     * Typical use cases include attaching an internal database id, request context, or metrics tags.
     */
    @Transient
    val transientData: Any? = null,

    /**
     * Ordered client-provided values to bind to the attestation. The values are stored under [CertificationRequestAttributeAttestationDescriptor.oid]
     * and decoded according to [CertificationRequestAttributeAttestationDescriptor.attributes].
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val toBeAttestedAttributes: CertificationRequestAttributeAttestationDescriptor? = null,

    /**
     * How the client authenticates the TBS CSR contents. [DataAuthentication.Signature] also proves possession of the
     * private key; [DataAuthentication.Hash] binds the data through the platform attestation nonce without signing.
     * @see DataAuthentication
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val dataAuth: DataAuthentication = DataAuthentication.Signature,

    ) {
    init {
        require(nonce.size <= 128) { "nonce too large! must be at most 128 bytes." }
        require(nonce.size >= 4) { "nonce too small! must be at least 4 bytes." }

    }

    /**
     * @param issuedAt The issuing time of the nonce. Useful to detect clock drifts and exit early.
     *  This is not considered sensible information, as clocks must be in sync anyhow.
     *  @param validity How long this nonce is considered valid.
     *  @param timeZone The server timezone. Purely diagnostic, since the [Instant] used for [issuedAt] is UTC by definition.
     *  Can be omitted if the server does not want to disclose this information
     *  @param nonce The nonce chosen by the server. Must be at most 128 bytes long, as
     *  [this is the largest nonce size supported by Android](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestationChallenge(byte%5B%5D)).
     *  @param attestationEndpoint The endpoint to post the signed CSR or unsigned TBS CSR containing the proof to.
     *  @param proofOID The OID of the TBS CSR attribute carrying the attestation statement.
     *  @param genericDeviceNameOID Whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16" with the attestation proof).
     *  Setting this to an OID other than `null` will include a device name on a best-effort basis. Defaults to `null` (i.e., no device name will be included).
     *  @param keyConstraints Specifies key constraints for the client.
     *  @param additionalPayload Optional user-defined payload. See [additionalPayload] for serialization requirements.
     *  @param transientData Optional runtime-only attachment. Not serialized and excluded from equality/hashing.
     *  @param toBeAttestedAttributes Optional ordered client-provided values to bind to the attestation.
     *  @param dataAuth Authentication mode for the TBS CSR contents.
     *
     * @throws IllegalArgumentException in case the [nonce] is larger than 128 bytes or shorter than 4 bytes
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        issuedAt: Instant,
        validity: Duration,
        timeZone: TimeZone? = null,
        nonce: ByteArray,
        attestationEndpoint: String,
        proofOID: ObjectIdentifier,
        genericDeviceNameOID: ObjectIdentifier? = null,
        keyConstraints: KeyConstraints? = null,
        additionalPayload: Map<String, Constrained>? = null,
        transientData: Any? = null,
        toBeAttestedAttributes: CertificationRequestAttributeAttestationDescriptor? = null,
        dataAuth: DataAuthentication = DataAuthentication.Signature,
    ) : this(
        issuedAt = issuedAt,
        validity = validity,
        timeZone = timeZone,
        nonce = nonce,
        attestationEndpoint = attestationEndpoint,
        proofOID = proofOID,
        genericDeviceNameOID = genericDeviceNameOID,
        version = if (dataAuth == DataAuthentication.Signature && toBeAttestedAttributes == null) 2 else CURRENT_VERSION,
        keyConstraints = keyConstraints,
        additionalPayload = additionalPayload,
        transientData = transientData,
        toBeAttestedAttributes = toBeAttestedAttributes,
        dataAuth = dataAuth,
    )

    /**
     * Lazily-evaluated property
     */
    val validUntil: Instant by lazy { issuedAt + validity }

    /**
     * Encapsulates the nonce encoded into a [KnownOIDs.serialNumber] RDN component for easier parsing
     */
    fun getRdnSerialNumber(): AttributeTypeAndValue = AttributeTypeAndValue.Other(
        KnownOIDs.serialNumber, Asn1String.Printable(
            nonce.toHexString(HexFormat.UpperCase)
        )
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationChallenge) return false

        if (genericDeviceNameOID != other.genericDeviceNameOID) return false
        if (version != other.version) return false
        if (issuedAt != other.issuedAt) return false
        if (validity != other.validity) return false
        if (timeZone != other.timeZone) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (attestationEndpoint != other.attestationEndpoint) return false
        if (proofOID != other.proofOID) return false
        if (keyConstraints != other.keyConstraints) return false
        if (additionalPayload != other.additionalPayload) return false
        if (validUntil != other.validUntil) return false
        if (toBeAttestedAttributes != other.toBeAttestedAttributes) return false
        if (dataAuth != other.dataAuth) return false

        return true
    }

    override fun hashCode(): Int {
        var result = genericDeviceNameOID.hashCode()
        result = 31 * result + (version ?: 0)
        result = 31 * result + issuedAt.hashCode()
        result = 31 * result + validity.hashCode()
        result = 31 * result + (timeZone?.hashCode() ?: 0)
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + attestationEndpoint.hashCode()
        result = 31 * result + proofOID.hashCode()
        result = 31 * result + (keyConstraints?.hashCode() ?: 0)
        result = 31 * result + (additionalPayload?.hashCode() ?: 0)
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + toBeAttestedAttributes.hashCode()
        result = 31 * result + dataAuth.hashCode()
        return result
    }

    /**
     * Lets the verifier describe an ordered list of client-provided values carried in one dedicated CertificationRequestInfo attribute.
     *
     * [oid] identifies the CertificationRequestInfo attribute. Each value is encoded by position using the corresponding entry in [attributes].
     */
    @Serializable
    data class CertificationRequestAttributeAttestationDescriptor(
        @Serializable(with = ObjectIdentifierStringSerializer::class)
        val oid: ObjectIdentifier,
        val attributes: List<AttributeAttestationDescriptor>
    ) {
        init {
            require(attributes.isNotEmpty()) { "attributes can't be empty!" }
            require(attributes.size == attributes.distinctBy { it.name }.size) { "attributes names must be distinct!" }
        }
    }

    /**
     * Describes one client-provided value requested by the verifier.
     *
     * [name] is application-facing metadata, [type] determines ASN.1 encoding, and [required] controls whether an
     * encoded ASN.1 `NULL` is accepted for this position.
     */
    @Serializable
    data class AttributeAttestationDescriptor(val name: String, val type: PrimitiveType, val required: Boolean = true)

    companion object {
        const val CURRENT_VERSION: Int = 3
    }
}

/**
 * Tries to extract an attestation statement from a TBS CSR based on the `proofOID` specified in [challenge]
 */
fun TbsCertificationRequest.attestationStatementForChallenge(challenge: AttestationChallenge): KmmResult<Attestation> =
    attestationStatementForOid(challenge.proofOID)


/**
 * Tries to extract an attestation statement from a TBS CSR, given it is present as an attribute with [oid]
 */
fun TbsCertificationRequest.attestationStatementForOid(oid: ObjectIdentifier): KmmResult<Attestation> =
    catching {
        attributes.find { it.oid == oid }?.value?.singleOrNull()
            ?.let {
                it.asPrimitive()
                val json = Asn1String.decodeFromTlv(it.asPrimitive()).value
                requireBoundedArrayNesting(json)
                Attestation.fromJSON(json)
            }
            ?: throw Asn1StructuralException("Attestation statement not present")
    }

/** Max JSON container-nesting depth accepted before parsing. */
const val MAX_JSON_NESTING_DEPTH = 64

/** Scans [json] for excessive object or array nesting without parsing it. Brackets inside string
 *  literals (keys/values) are ignored. Throws [SerializationException] if depth exceeds
 *  [MAX_JSON_NESTING_DEPTH]. Cheap, single linear pass, no allocation. */
fun requireBoundedArrayNesting(json: String) {
    var depth = 0
    val openers = CharArray(MAX_JSON_NESTING_DEPTH)
    var inString = false
    var escaped = false
    for (c in json) {
        if (inString) {
            when {
                //@formatter:off
                escaped   -> escaped  = false
                c == '\\' -> escaped  = true
                c == '"'  -> inString = false
                //@formatter:on
            }
            continue
        }
        when (c) {
            '"' -> inString = true
            '[', '{' -> {
                depth++
                if (depth > MAX_JSON_NESTING_DEPTH)
                    throw SerializationException(
                        "JSON nesting exceeds $MAX_JSON_NESTING_DEPTH"
                    )
                openers[depth - 1] = c
            }

            ']', '}' -> {
                val expectedOpener = if (c == ']') '[' else '{'
                if (depth == 0 || openers[depth - 1] != expectedOpener)
                    throw SerializationException("Mismatched JSON container delimiter")
                depth--
            }
        }
    }
    if (depth != 0) throw SerializationException("Unclosed JSON container")
}

/**
 * Tries to extract the nonce from a TBS CSR's subject name, given it is encoded into an RDN containing a [KnownOIDs.serialNumber]
 */
val TbsCertificationRequest.nonce: KmmResult<ByteArray>
    get() = catching {
        val noncesRecovered =
            subjectName.mapNotNull { name -> name.attrsAndValues.find { attributeTypeAndValue -> attributeTypeAndValue.oid == KnownOIDs.serialNumber } }
        if (noncesRecovered.isEmpty()) throw Asn1StructuralException("No nonce present")
        else if (noncesRecovered.size != 1) throw Asn1StructuralException("More than one nonce present!")
        noncesRecovered.first().value.asPrimitive().decodeToString().hexToByteArray()
    }

/**
 * Tries to extract a device name from a TBS CSR, given it is present as an attribute with [oid]
 */
fun TbsCertificationRequest.deviceNameForOid(oid: ObjectIdentifier): String? = catchingUnwrapped {
    attributes.find { it.oid == oid }?.value?.singleOrNull()?.asPrimitive()
        ?.decodeToUtf8String()?.value
}.getOrNull()

/**
 * Tries to extract a device name from a TBS CSR if `genericDeviceNameOID` is specified in [challenge]
 */
fun TbsCertificationRequest.deviceNameForChallenge(challenge: AttestationChallenge): String? =
    challenge.genericDeviceNameOID?.let { oid ->
        deviceNameForOid(oid)
    }

/**
 * @see TbsCertificationRequest.deviceName
 */
fun Pkcs10CertificationRequest.deviceNameForOid(oid: ObjectIdentifier): String? = tbsCsr.deviceNameForOid(oid)

/**
 * @see TbsCertificationRequest.deviceNameForChallenge
 */
fun Pkcs10CertificationRequest.deviceNameForChallenge(challenge: AttestationChallenge): String? =
    tbsCsr.deviceNameForChallenge(challenge)
