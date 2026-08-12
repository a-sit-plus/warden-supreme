package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest

/**
 * An authenticated client-to-verifier transport carrying the platform-generated attestation statement.
 *
 * [Signed] carries a complete PKCS#10 CSR and proves possession of the attested private key. [Hashed] carries an unsigned
 * CertificationRequestInfo (TBS CSR) whose contents are bound through the platform attestation nonce, but does not prove
 * possession. The latter does not carry its hash algorithm: the verifier obtains it from the matching
 * [AttestationChallenge].
 */
sealed interface AttestationProof {
    val data: Asn1Encodable<Asn1Sequence>

    /** A complete PKCS#10 CSR whose signature proves possession of the attested private key. */
    class Signed(override val data: Pkcs10CertificationRequest) : AttestationProof

    /** An unsigned TBS CSR whose non-key, non-proof contents are authenticated using the challenge's hash algorithm. */
    class Hashed(override val data: TbsCertificationRequest) : AttestationProof

    companion object
}

/** Returns the unsigned certification-request information carried by either transport shape. */
val AttestationProof.tbsCsr
    get() = when (this) {
        is AttestationProof.Signed -> data.tbsCsr
        is AttestationProof.Hashed -> data
    }
