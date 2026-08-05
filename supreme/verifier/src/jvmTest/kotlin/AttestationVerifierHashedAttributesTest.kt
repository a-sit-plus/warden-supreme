@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

private val hashedAttributeRequest = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
    ObjectIdentifier("1.3.6.1.4.1.60387.2"),
    listOf(
        AttestationChallenge.AttributeAttestationDescriptor("required", PrimitiveType.STRING),
        AttestationChallenge.AttributeAttestationDescriptor("optional", PrimitiveType.INT, required = false),
    ),
)

private data class HashedProofFixture(
    val verifier: AttestationVerifier,
    val proof: AttestationProof.Hashed,
)

private suspend fun hashedProofFixture(
    values: List<Primitive>,
    includeAttribute: Boolean = true,
    matchingHash: Boolean = true,
    encodedValuesOverride: Asn1Sequence? = null,
): HashedProofFixture {
    val encodedValues = encodedValuesOverride ?: values.toSequence()
    val nonce = Random(encodedValues.hashCode()).nextBytes(16)
    val authentication = DataAuthentication.Hash(Digest.SHA256)
    val attributes = buildList {
        if (includeAttribute) add(Pkcs10CertificationRequestAttribute(hashedAttributeRequest.oid, encodedValues))
    }
    val hashInput = AttestationHashInput(
        subjectName = listOf(RelativeDistinguishedName(AttestationChallenge(
            issuedAt = fixedClock.now(),
            validity = kotlin.time.Duration.ZERO,
            nonce = nonce,
            attestationEndpoint = attestationEndpoint,
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
        ).getRdnSerialNumber())),
        extensions = emptyList(),
        attributes = attributes,
    )
    val digest = authentication.algorithm.digest(hashInput.encodeToDer())
    if (!matchingHash) digest[0] = (digest[0].toInt() xor 1).toByte()

    val fake = createFakeAndroidAttestation(
        challenge = digest,
        packageName = fakeAndroidPackage,
        signatureDigest = fakeAndroidSignerDigest,
    )
    val verifier = AttestationVerifier(
        makoto = fixedMakoto(
            androidConfigForFake(
                packageName = fakeAndroidPackage,
                signatureDigest = fakeAndroidSignerDigest,
                trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
            )
        ),
        genericDeviceNameOID = null,
        nonceGenerator = suspend { nonce },
    )
    val challenge = verifier.issueChallenge(
        attestationEndpoint,
        keyConstraints = WardenDefaults.KeyConstraints.p256Signer,
        toBeAttestedAttributes = hashedAttributeRequest,
        dataAuth = authentication,
    )
    val tbsCsr = hashInput.toTbsCsr(
        fake.leafKeyPair.public.toCryptoPublicKey().getOrThrow(),
        Pkcs10CertificationRequestAttribute(
            challenge.proofOID,
            Asn1String.UTF8(fake.attestationJson()).encodeToTlv(),
        ),
    )
    return HashedProofFixture(verifier, AttestationProof.Hashed(tbsCsr))
}

val AttestationVerifierHashedAttributesTest by matrixSuite {
    test("matching hash with present requested attributes succeeds") {
        val fixture = hashedProofFixture(listOf("present", 42))

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Success>()
    }

    test("mismatching hash is rejected") {
        val fixture = hashedProofFixture(listOf("present", 42), matchingHash = false)

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

    test("missing requested CSR attribute is rejected") {
        val fixture = hashedProofFixture(listOf("present", 42), includeAttribute = false)
        var callbackError: PreAttestationError.ClientDataValidation? = null

        val failure = fixture.verifier.verifyAttestation(
            fixture.proof,
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = { emptyList() },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_EXTRACTION
    }

    test("missing required value is rejected") {
        val fixture = hashedProofFixture(listOf(null, 42))
        var callbackError: PreAttestationError.ClientDataValidation? = null

        val failure = fixture.verifier.verifyAttestation(
            fixture.proof,
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = { emptyList() },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_MISMATCH
    }

    test("missing optional value succeeds") {
        val fixture = hashedProofFixture(listOf("present", null))

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Success>()
    }

    test("wrong ASN.1 primitive type is rejected") {
        val malformed = Asn1.Sequence {
            +Asn1.ExplicitlyTagged(0u) { +Asn1.Int(7) }
            +Asn1.ExplicitlyTagged(1u) { +Asn1.Int(42) }
        }
        val fixture = hashedProofFixture(emptyList(), encodedValuesOverride = malformed)

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

    test("wrong ASN.1 position tag is rejected") {
        val malformed = Asn1.Sequence {
            +Asn1.ExplicitlyTagged(1u) { +Asn1String.UTF8("present") }
            +Asn1.ExplicitlyTagged(1u) { +Asn1.Int(42) }
        }
        val fixture = hashedProofFixture(emptyList(), encodedValuesOverride = malformed)

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

    test("extra requested-attribute sequence element is rejected") {
        val malformed = Asn1.Sequence {
            +Asn1.ExplicitlyTagged(0u) { +Asn1String.UTF8("present") }
            +Asn1.ExplicitlyTagged(1u) { +Asn1.Int(42) }
            +Asn1.ExplicitlyTagged(2u) { +Asn1String.UTF8("extra") }
        }
        val fixture = hashedProofFixture(emptyList(), encodedValuesOverride = malformed)

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

    test("oversized integer attribute outside requested INT range is rejected") {
        val malformed = Asn1.Sequence {
            +Asn1.ExplicitlyTagged(0u) { +Asn1String.UTF8("present") }
            +Asn1.ExplicitlyTagged(1u) { +Asn1.Int(Long.MAX_VALUE) }
        }
        val fixture = hashedProofFixture(emptyList(), encodedValuesOverride = malformed)

        fixture.verifier.verifyAttestation(fixture.proof, certificateIssuer = { emptyList() })
            .shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }
}
