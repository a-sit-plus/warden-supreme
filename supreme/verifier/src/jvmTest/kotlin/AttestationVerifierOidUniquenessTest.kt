@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
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
            attestableAttributes = requested,
        )
        val proof = Pkcs10CertificationRequestAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
        val duplicatedOid = when (kind) {
            "proof" -> challenge.proofOID
            "device" -> requireNotNull(challenge.genericDeviceNameOID)
            else -> requireNotNull(challenge.toBeAttestedAttributes).oid
        }
        val duplicate = Pkcs10CertificationRequestAttribute(
            duplicatedOid,
            Asn1String.UTF8("duplicate").encodeToTlv(),
        )
        val attributes = if (kind == "proof") listOf(proof, duplicate) else listOf(proof, duplicate, duplicate)
        val csr = createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, attributes)
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
        callbackError?.reason shouldBe PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID
    }

    data(
        "duplicate OID kind",
        listOf(
            Triple("attributes", PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID) { proof: Pkcs10CertificationRequestAttribute ->
                listOf(
                    proof,
                    Pkcs10CertificationRequestAttribute(duplicateOid, Asn1String.UTF8("one").encodeToTlv()),
                    Pkcs10CertificationRequestAttribute(duplicateOid, Asn1String.UTF8("two").encodeToTlv()),
                )
            },
            Triple("extensions", PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_EXTENSION_OID) { proof: Pkcs10CertificationRequestAttribute ->
                val extensions = listOf(
                    X509CertificateExtension(duplicateOid, false, Asn1.OctetString(byteArrayOf(1))),
                    X509CertificateExtension(duplicateOid, true, Asn1.OctetString(byteArrayOf(2))),
                )
                listOf(
                    proof,
                    Pkcs10CertificationRequestAttribute(
                        extensionRequestOid,
                        Asn1.Sequence { extensions.forEach { +it } },
                    ),
                )
            },
        ),
        nameFn = { _, value -> value.first },
    ) test { (_, expectedReason, attributes) ->
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val challenge = verifier.issueChallenge(attestationEndpoint)
        val proof = Pkcs10CertificationRequestAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
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

    test("non-canonical attribute order is rejected as CONTENT") {
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val challenge = verifier.issueChallenge(attestationEndpoint)
        val proof = Pkcs10CertificationRequestAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
        )
        val other = Pkcs10CertificationRequestAttribute(
            duplicateOid,
            Asn1String.UTF8("value").encodeToTlv(),
        )
        val nonCanonical = Asn1.SetOf { listOf(proof, other).forEach { +it } }
            .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it.asSequence()) }
            .reversed()
        val csr = createCsrWithAttributes(challenge, fixture.fake.leafKeyPair, nonCanonical)

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
                Pkcs10CertificationRequestAttribute(
                    challenge.proofOID,
                    Asn1String.UTF8(fixture.fake.attestationJson()).encodeToTlv(),
                ),
                Pkcs10CertificationRequestAttribute(
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
