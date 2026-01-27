package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
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
import kotlinx.serialization.Serializable
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * A generic representation of a challenge sent the server.
 */
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
     * The endpoint to post the CSR containing the attestation proof to.
     */
    val attestationEndpoint: String,

    /**
     * The OID to be used for encoding the attestation proof into the signed CSR used to transfer the proof.
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


    ) {
    init {
        if (nonce.size > 128) throw IllegalArgumentException("nonce too large! must be at most 128 bytes.")
    }

    /**
     * @param issuedAt The issuing time of the nonce. Useful to detect clock drifts and exit early.
     *  This is not considered sensible information, as clocks must be in sync anyhow.
     *  @param validity How long this nonce is considered valid.
     *  @param timeZone The server timezone. Purely diagnostic, since the [Instant] used for [issuedAt] is UTC by definition.
     *  Can be omitted if the server does not want to disclose this information
     *  @param nonce The nonce chosen by the server. Must be at most 128 bytes long, as
     *  [this is the largest nonce size supported by Android](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestationChallenge(byte%5B%5D)).
     *  @param attestationEndpoint The endpoint to post the CSR containing the attestation proof to.
     *  @param proofOID The OID to be used for encoding the attestation proof into the signed CSR used to transfer the proof.
     *  @param genericDeviceNameOID Whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16" with the attestation proof).
     *  Setting this to an OID other than `null` will include a device name on a best-effort basis. Defaults to `null` (i.e., no device name will be included).
     *  @param keyConstraints Specifies key constraints for the client.
     *
     * @throws IllegalArgumentException in case the [nonce] is larger than 128 bytes
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
    ) : this(
        issuedAt = issuedAt,
        validity = validity,
        timeZone = timeZone,
        nonce = nonce,
        attestationEndpoint = attestationEndpoint,
        proofOID = proofOID,
        genericDeviceNameOID = genericDeviceNameOID,
        version = CURRENT_VERSION,
        keyConstraints = keyConstraints,
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
        if (validUntil != other.validUntil) return false

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
        result = 31 * result + validUntil.hashCode()
        return result
    }

    companion object {
        const val CURRENT_VERSION: Int = 2
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
                Attestation.fromJSON(Asn1String.decodeFromTlv(it.asPrimitive()).value)
            }
            ?: throw Asn1StructuralException("Attestation statement not present")
    }

@Deprecated("Misnomer. To be removed in 1.1", replaceWith = ReplaceWith("nonce"))
val TbsCertificationRequest.challenge get() = nonce

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


//TODO: remove in 1.1!
@Deprecated(
    "Use `deviceNameForOid(WardenDefaults.OIDs.DEVICE_NAME)` instead to emulate old behaviour, but you should really specify whatever OID you have set to convey a generic device. Will be removed in 1.1.",
    ReplaceWith("deviceNameForOid(deviceNameOid)"),
    DeprecationLevel.ERROR
)
val TbsCertificationRequest.deviceName: String?
    get() = deviceNameForOid(WardenDefaults.OIDs.DEVICE_NAME)


//TODO: remove in 1.1!
@Deprecated(
    "Use `deviceNameForOid(WardenDefaults.OIDs.DEVICE_NAME)` instead to emulate old behaviour, but you should really specify whatever OID you have set to convey a generic device. Will be removed in 1.1",
    ReplaceWith("deviceNameForOid(deviceNameOid)"),
    DeprecationLevel.ERROR
)
val Pkcs10CertificationRequest.deviceName: String? get() = tbsCsr.deviceNameForOid(WardenDefaults.OIDs.DEVICE_NAME)