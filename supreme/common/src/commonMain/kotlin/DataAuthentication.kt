@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.Digest
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Selects how the client authenticates the data surrounding an attestation proof.
 *
 * [Signature] signs the complete CertificationRequestInfo with the freshly attested key. This authenticates its
 * subject, attributes, extensions, and public key and proves possession of the private key.
 *
 * [Hash] is intended for ceremonies where proof of possession is not required, for example when using the private key
 * would trigger user authentication. The client constructs an [AttestationHashInput] containing the TBS CSR version,
 * subject, extensions, and all attributes except the attestation proof. Its DER encoding is hashed with [Hash.algorithm].
 * **The resulting digest is used as nonce and fed into the key attestation flow.** The client responds with an
 * **unsigned CertificationRequestInfo** completed with the generated public key and attestation proof. The verifier
 * verifies the attestation, checks that its key equals the TBS CSR public key, removes the public key and proof, and
 * recomputes the digest. This binds every other TBS CSR field but deliberately provides no proof of possession.
 *
 */
@Serializable(with = DataAuthentication.Serializer::class)
sealed interface DataAuthentication {

    /** Authenticate the TBS CSR with a signature made by the attested key, thereby proving possession. */
    @Serializable(with = DataAuthentication.Serializer::class)
    object Signature : DataAuthentication

    /** Authenticate the TBS CSR hash input through the platform attestation nonce, without proving possession. */
    @Serializable(with = DataAuthentication.Serializer::class)
    data class Hash
    /**
     * [Digest.SHA1] is considered insecure and prohibited
     * @throws IllegalArgumentException if SHA-1 is used
     */
    @Throws(IllegalArgumentException::class)
    constructor(val algorithm: Digest) : DataAuthentication {
        init {
            require(algorithm != Digest.SHA1) {"SHA-1 is insecure"}
        }
    }

    object Serializer : KSerializer<DataAuthentication> {
        private val delegate = SerializedDataAuthentication.serializer()
        override val descriptor: SerialDescriptor = delegate.descriptor

        override fun serialize(encoder: Encoder, value: DataAuthentication) = delegate.serialize(
            encoder,
            when (value) {
                Signature -> SerializedDataAuthentication(SerializedDataAuthentication.Type.SIGNATURE)
                is Hash -> SerializedDataAuthentication(SerializedDataAuthentication.Type.HASH, value.algorithm)
            },
        )

        override fun deserialize(decoder: Decoder): DataAuthentication = delegate.deserialize(decoder).let {
            when (it.type) {
                SerializedDataAuthentication.Type.SIGNATURE-> Signature
                SerializedDataAuthentication.Type.HASH -> Hash(requireNotNull(it.algorithm) { "Missing DataAuthentication.algorithm" })
            }
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
private data class SerializedDataAuthentication(
    val type: Type,
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val algorithm: Digest? = null,
) {
    @Serializable
    enum class Type {
        SIGNATURE,
        HASH
    }
}
