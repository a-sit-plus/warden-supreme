package at.asitplus.attestation.data

import com.google.android.attestation.ParsedAttestationRecord
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*

internal val certificateFactory = CertificateFactory.getInstance("X.509")
internal val mimeDecoder = Base64.getMimeDecoder()

internal val ecKeyFactory = KeyFactory.getInstance("EC")
internal val rsaKeyFactory = KeyFactory.getInstance("RSA")


class AttestationData(
    val name: String, challengeB64: String, val attestationProofB64: List<String>,
    isoDate: String,
    val pubKeyB64: String? = null,
    val packageOverride: String? = null,
    val isProductionOverride: Boolean? = null
) {

    val verificationDate: Date = Date.from(Instant.parse(isoDate))

    val challenge by lazy { mimeDecoder.decode(challengeB64) }

    val publicKey: PublicKey? by lazy {
        pubKeyB64?.let { mimeDecoder.decode(it) }
            ?.let { (if (it.size < 2048) ecKeyFactory else rsaKeyFactory).generatePublic(X509EncodedKeySpec(it)) }
    }
}

val AttestationData.attestationCertChain: List<X509Certificate>
    get() = attestationProofB64.map {
        certificateFactory
            .generateCertificate(mimeDecoder.decode(it).inputStream()) as X509Certificate

    }
val AttestationData.androidAttestationRecord: ParsedAttestationRecord?
    get() = if (attestationProofB64.size > 2)
        ParsedAttestationRecord.createParsedAttestationRecord(attestationCertChain)
    else null
