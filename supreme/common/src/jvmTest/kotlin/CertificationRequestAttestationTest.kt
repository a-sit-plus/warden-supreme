import at.asitplus.KmmResult
import at.asitplus.attestation.supreme.*
import at.asitplus.attestation.supreme.AttestationProof.Hashed
import at.asitplus.attestation.supreme.AttestationProof.Signed
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

private val proofOid = ObjectIdentifier("1.3.6.1.4.1.60387.99")
private val publicKey = CryptoPublicKey.EC.fromUncompressed(
    ECCurve.SECP_256_R_1,
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296".hexToByteArray(),
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5".hexToByteArray(),
)

private data class RoundTripCase(
    val subjectName: List<RelativeDistinguishedName>,
    val extensions: List<X509CertificateExtension>,
    val version: Int,
    val attributes: List<Pkcs10CertificationRequestAttribute>,
    val proof: Pkcs10CertificationRequestAttribute,
)

private val bytesArb = Arb.byteArray(Arb.int(0..32), Arb.byte())
private val stringArb = bytesArb.map(ByteArray::toHexString)
private val subjectNameArb = Arb.list(
    Arb.list(stringArb, 1..3).map { values ->
        RelativeDistinguishedName(values.mapIndexed { index, value ->
            AttributeTypeAndValue.Other(
                ObjectIdentifier("1.3.6.1.4.1.60387.1.${index + 1}"),
                Asn1String.UTF8(value),
            )
        })
    },
    0..3,
)
private val extensionsArb = Arb.list(Arb.bind(bytesArb, Arb.boolean(), ::Pair), 0..3).map { values ->
    values.mapIndexed { index, (value, critical) ->
        X509CertificateExtension(
            ObjectIdentifier("1.3.6.1.4.1.60387.2.${index + 1}"),
            critical,
            Asn1.OctetString(value),
        )
    }
}
private val attributesArb = Arb.list(Arb.list(stringArb, 1..3), 0..4).map { values ->
    values.mapIndexed { index, attributeValues ->
        Pkcs10CertificationRequestAttribute(
            ObjectIdentifier("1.3.6.1.4.1.60387.${index + 101}"),
            attributeValues.map { Asn1String.UTF8(it).encodeToTlv() },
        )
    }
}
private val roundTripArb = Arb.bind(
    subjectNameArb,
    extensionsArb,
    Arb.int(),
    attributesArb,
    stringArb,
) { subjectName, extensions, version, attributes, proof ->
    RoundTripCase(
        subjectName,
        extensions,
        version,
        attributes,
        Pkcs10CertificationRequestAttribute(proofOid, Asn1String.UTF8(proof).encodeToTlv()),
    )
}

val CertificationRequestAttestationTest by matrixSuite {
    property("hash input and TBS CSR round-trip exactly", roundTripArb, iterations = 1024) test { case ->
        with(case) {
            val hashInput = AttestationHashInput(
                subjectName = subjectName,
                extensions = extensions,
                version = version,
                attributes = attributes,
            )
            val received = hashInput.toTbsCsr(publicKey, proof)
            received.attributes.map { it.encodeToTlv() } shouldBe
                    Asn1.SetOf { (hashInput.attributes + proof).forEach { +it } }.toList()
            val decodedHashInput = AttestationHashInput.decodeFromTlv(hashInput.encodeToTlv())
            decodedHashInput.encodeToDer().contentEquals(hashInput.encodeToDer()) shouldBe true
            received.toHashInput(proofOid).encodeToDer().contentEquals(hashInput.encodeToDer()) shouldBe true
            received.toHashInput(proofOid).toTbsCsr(received.publicKey, proof).encodeToDer()
                .contentEquals(received.encodeToDer()) shouldBe true
        }
    }

    "normalization requires exactly one proof attribute" {
        val tbsCsr = TbsCertificationRequest(emptyList(), publicKey, extensions = emptyList())
        shouldThrow<IllegalArgumentException> {
            tbsCsr.toHashInput(proofOid)
        }

        val proof = Pkcs10CertificationRequestAttribute(proofOid, Asn1String.UTF8("proof").encodeToTlv())
        shouldThrow<IllegalArgumentException> {
            tbsCsr.copy(attributes = listOf(proof, proof)).toHashInput(proofOid)
        }
    }

    "DER transport decoding infers signed and unsigned CSR shapes" {
        val tbsCsr = TbsCertificationRequest(emptyList(), publicKey, extensions = emptyList())
        val csr = Pkcs10CertificationRequest(
            tbsCsr,
            X509SignatureAlgorithm.RS256,
            CryptoSignature.RSA(byteArrayOf(1)),
        )

        AttestationProof.decodeFromDer(tbsCsr.encodeToDer()).getOrThrow()
            .shouldBeInstanceOf<AttestationProof.Hashed>()
        AttestationProof.decodeFromDer(csr.encodeToDer()).getOrThrow()
            .shouldBeInstanceOf<AttestationProof.Signed>()
        AttestationProof.decodeFromDer(byteArrayOf()).isFailure shouldBe true
    }

    "attested attributes are exposed by configured name for both transports" {
        val attributeOid = ObjectIdentifier("2.25.304198582559398858370235454530489176240")
        val requested = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
            attributeOid,
            listOf(
                AttestationChallenge.AttributeAttestationDescriptor("accountId", PrimitiveType.STRING),
                AttestationChallenge.AttributeAttestationDescriptor("riskScore", PrimitiveType.INT, required = false),
            ),
        )
        val challenge = AttestationChallenge(
            issuedAt = Clock.System.now(),
            validity = 5.minutes,
            nonce = byteArrayOf(1, 2, 3, 4),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = proofOid,
            toBeAttestedAttributes = requested,
        )
        val attribute = Pkcs10CertificationRequestAttribute(
            attributeOid,
            listOf<Primitive>("account-123", null).toSequence(),
        )
        val tbsCsr = TbsCertificationRequest(emptyList(), publicKey, attributes = listOf(attribute))
        val csr = Pkcs10CertificationRequest(tbsCsr, X509SignatureAlgorithm.RS256, CryptoSignature.RSA(byteArrayOf(1)))

        listOf(AttestationProof.Hashed(tbsCsr), AttestationProof.Signed(csr)).forEach { received ->
            with(challenge) {
                received.attestedAttributes shouldBe mapOf("accountId" to "account-123", "riskScore" to null)
            }
        }
    }
}

private fun AttestationProof.Companion.decodeFromDer(src: ByteArray): KmmResult<AttestationProof> = catching {
    catchingUnwrapped {
        Signed(Pkcs10CertificationRequest.decodeFromDer(src))
    }.getOrElse {
        Hashed(TbsCertificationRequest.decodeFromDer(src))
    }
}
