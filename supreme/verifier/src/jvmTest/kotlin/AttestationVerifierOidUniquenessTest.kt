@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1CustomStructure
import at.asitplus.awesn1.TagClass
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.Signum
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.awesn1.serialization.decodeFromTlv

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.CsrAttribute
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val duplicateOid = ObjectIdentifier("1.3.6.1.4.1.60387.999")
private val extensionRequestOid = ObjectIdentifier("1.2.840.113549.1.9.14")

val AttestationVerifierOidUniquenessTest by matrixSuite {
    data(
        "specific duplicate attribute OIDs",
        listOf("proof", "device", "requested"),
    ) test { kind ->
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val requested = if (kind == "requested") AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
            duplicateOid,
            listOf(AttestationChallenge.AttributeAttestationDescriptor("value", PrimitiveType.STRING)),
        ) else null
        val challenge = verifier.issueChallenge(
            attestationEndpoint,
            toBeAttestedAttributes = requested,
        )
        val proof = CsrAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
        val duplicatedOid = when (kind) {
            "proof" -> challenge.proofOID
            "device" -> requireNotNull(challenge.genericDeviceNameOID)
            else -> requireNotNull(challenge.toBeAttestedAttributes).oid
        }
        val duplicate = CsrAttribute(
            duplicatedOid,
            Asn1String.UTF8("duplicate").encodeToTlv(),
        )
        val attributes = if (kind == "proof") listOf(proof, duplicate) else listOf(proof, duplicate, duplicate)
        shouldThrow<IllegalArgumentException> {
            createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, attributes)
        }
        val valid = createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, listOf(proof))
        val malformed = Asn1Sequence(
            Signum.Der.encodeToTlv(valid.tbsCsr).asSequence().children.take(3) +
                    Asn1CustomStructure(attributes.map { Signum.Der.encodeToTlv(it) }, 0uL, TagClass.CONTEXT_SPECIFIC),
        )
        shouldThrowAny { Signum.Der.decodeFromTlv<TbsCertificationRequest>(malformed) }
    }

    data(
        "duplicate OID kind",
        listOf(
            Triple("attributes", PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID) { proof: CsrAttribute ->
                listOf(
                    proof,
                    CsrAttribute(duplicateOid, Asn1String.UTF8("one").encodeToTlv()),
                    CsrAttribute(duplicateOid, Asn1String.UTF8("two").encodeToTlv()),
                )
            },
            Triple("extensions", PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_EXTENSION_OID) { proof: CsrAttribute ->
                val extensions = listOf(
                    X509CertificateExtension(duplicateOid, false, Asn1.OctetString(byteArrayOf(1))),
                    X509CertificateExtension(duplicateOid, true, Asn1.OctetString(byteArrayOf(2))),
                )
                listOf(
                    proof,
                    CsrAttribute(
                        extensionRequestOid,
                        Asn1.Sequence { extensions.forEach { +Signum.Der.encodeToTlv(it) } },
                    ),
                )
            },
        ),
        nameFn = { _, value -> value.first },
    ) test { (_, expectedReason, attributes) ->
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val challenge = verifier.issueChallenge(attestationEndpoint)
        val proof = CsrAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
        if (expectedReason == PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID) {
            shouldThrow<IllegalArgumentException> {
                createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, attributes(proof))
            }
        } else {
            val csr = createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, attributes(proof))

            var callbackError: PreAttestationError.ClientDataValidation? = null
            val failure = verifier.verifyAttestation(
                AttestationProof.Signed(csr),
                onPreAttestationError = {
                    callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                    "callback"
                },
                certificateIssuer = { emptyList() },
            ).shouldBeInstanceOf<AttestationResponse.Failure>()

            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            failure.explanation shouldBe "callback"
            callbackError?.reason shouldBe expectedReason
        }
    }

    test("non-canonical attribute order is rejected as CONTENT") {
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val challenge = verifier.issueChallenge(
            attestationEndpoint,
            dataAuth = DataAuthentication.Hash(Digest.SHA256),
        )
        val proof = CsrAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
        val other = CsrAttribute(
            duplicateOid,
            Asn1String.UTF8("value").encodeToTlv(),
        )
        val nonCanonical = Asn1.SetOf { listOf(proof, other).forEach { +Signum.Der.encodeToTlv(it) } }
            .map { Signum.Der.decodeFromTlv<CsrAttribute>(it.asSequence()) }
            .reversed()
        val csr = createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, nonCanonical)

        var callbackError: PreAttestationError.ClientDataValidation? = null
        val failure = verifier.verifyAttestation(
            AttestationProof.Hashed(csr.tbsCsr),
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = { emptyList() },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.NON_CANONICAL_CSR_ATTRIBUTE_ORDER
    }

    test("malformed extension request invokes validation callback") {
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val challenge = verifier.issueChallenge(attestationEndpoint)
        val csr = createCsrWithAttributes(
            challenge,
            fixture.fake.leafKeyPair,
            listOf(
                CsrAttribute(
                    challenge.proofOID,
                    Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
                ),
                CsrAttribute(
                    extensionRequestOid,
                    Asn1String.UTF8("not extensions").encodeToTlv(),
                ),
            ),
        )
        var callbackError: PreAttestationError.ClientDataValidation? = null

        val failure = verifier.verifyAttestation(
            AttestationProof.Signed(csr),
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = { emptyList() },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.MALFORMED_CSR_EXTENSION_REQUEST
    }
}
