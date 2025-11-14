package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.decodeToString
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
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
 * @throws IllegalArgumentException in case the nonce is larger than 128 bytes
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
     * The server timezone. Can be omitted if the server does not want to disclose this information
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
     * The endpoint to post the CSR containing the attestation proof to
     */
    val attestationEndpoint: String,

    /**
     * The OID to be used for encoding the attestation proof into the signed CSR used to transfer the proof.
     */
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val proofOID: ObjectIdentifier,

    /**
     * Indicates the wire format version
     */
    val version: Int? = null,

    /**
     * Specified key constraints for the client
     */
    val keyConstraints: KeyConstraints? = null,

    ) {
    init {
        if (nonce.size > 128) throw IllegalArgumentException("nonce too large! must be at most 128 bytes.")
    }

    constructor(
        issuedAt: Instant,
        validity: Duration,
        timeZone: TimeZone? = null,
        nonce: ByteArray,
        attestationEndpoint: String,
        proofOID: ObjectIdentifier,
        keyConstraints: KeyConstraints? = null,
    ) : this(
        issuedAt,
        validity,
        timeZone,
        nonce,
        attestationEndpoint,
        proofOID,
        version = 1,
        keyConstraints,
    )


    /**
     * Convenience constructor to pass two instants instead of instant and duration
     */
    constructor(
        issuedAt: Instant,
        validUntil: Instant,
        timeZone: TimeZone?,
        nonce: ByteArray,
        attestationEndpoint: String,
        proofOID: ObjectIdentifier,
        keyConstrains: KeyConstraints? = null,
    ) : this(
        issuedAt,
        validUntil - issuedAt,
        timeZone,
        nonce,
        attestationEndpoint,
        proofOID,
        version = 1,
        keyConstrains
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

        if (issuedAt != other.issuedAt) return false
        if (validity != other.validity) return false
        if (!nonce.contentEquals(other.nonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuedAt.hashCode()
        result = 31 * result + validity.hashCode()
        result = 31 * result + nonce.contentHashCode()
        return result
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


/**
 * Tries to extract the challenge from a TBS CSR's subject name, given it is encoded into an RDN containing a [KnownOIDs.serialNumber]
 */
val TbsCertificationRequest.challenge: KmmResult<ByteArray>
    get() = catching {
        val noncesRecovered =
            subjectName.mapNotNull { name -> name.attrsAndValues.find { attributeTypeAndValue -> attributeTypeAndValue.oid == KnownOIDs.serialNumber } }
        if (noncesRecovered.isEmpty()) throw Asn1StructuralException("No nonce present")
        else if (noncesRecovered.size != 1) throw Asn1StructuralException("More than one nonce present!")
        noncesRecovered.first().value.asPrimitive().decodeToString().hexToByteArray()
    }
