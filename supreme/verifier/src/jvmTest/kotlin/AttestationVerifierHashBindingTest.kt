@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val bindingExtensionRequestOid = ObjectIdentifier("1.2.840.113549.1.9.14")
private val bindingAttributeOid = ObjectIdentifier("2.25.206039601192291490934634330976917168161")
private val bindingExtensionOid = ObjectIdentifier("2.5.29.17")
private val bindingDeviceNameOid = ObjectIdentifier("2.25.206039601192291490934634330976917168163")

private data class HashBindingFixture(
    val verifier: AttestationVerifier,
    val proof: AttestationProof.Hashed,
)

private suspend fun hashBindingFixture(
    expectedAlgorithm: Digest = Digest.SHA256,
    attestedAlgorithm: Digest = expectedAlgorithm,
    genericDeviceNameOid: ObjectIdentifier? = null,
    attributes: List<Pkcs10CertificationRequestAttribute> = emptyList(),
    extensions: List<X509CertificateExtension> = emptyList(),
    mutate: (AttestationHashInput) -> AttestationHashInput = { it },
): HashBindingFixture {
    val nonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val challengeTemplate = AttestationChallenge(
        issuedAt = fixedClock.now(),
        validity = kotlin.time.Duration.ZERO,
        nonce = nonce,
        attestationEndpoint = attestationEndpoint,
        proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID = genericDeviceNameOid,
    )
    val hashInput = AttestationHashInput(
        subjectName = listOf(RelativeDistinguishedName(challengeTemplate.getRdnSerialNumber())),
        extensions = extensions,
        attributes = attributes,
    )
    val fake = createFakeAndroidAttestation(
        challenge = attestedAlgorithm.digest(hashInput.encodeToDer()),
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
        genericDeviceNameOID = genericDeviceNameOid,
        nonceGenerator = suspend { nonce },
    )
    val challenge = verifier.issueChallenge(
        attestationEndpoint,
        dataAuth = DataAuthentication.Hash(expectedAlgorithm),
    )
    val proof = Pkcs10CertificationRequestAttribute(
        challenge.proofOID,
        Asn1String.UTF8(fake.attestationJson()).encodeToTlv(),
    )
    return HashBindingFixture(
        verifier,
        AttestationProof.Hashed(
            mutate(hashInput).toTbsCsr(fake.leafKeyPair.public.toCryptoPublicKey().getOrThrow(), proof)
        ),
    )
}

private suspend fun HashBindingFixture.verify() =
    verifier.verifyAttestation(proof, certificateIssuer = { emptyList() })

private suspend fun HashBindingFixture.verifyRejected() =
    verify().shouldBeInstanceOf<AttestationResponse.Failure>().also {
        it.kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

val AttestationVerifierHashBindingTest by matrixSuite {
    test("subject mutation after hashed attestation is rejected") {
        hashBindingFixture { input ->
            AttestationHashInput(
                version = input.version,
                subjectName = input.subjectName + RelativeDistinguishedName(
                    AttributeTypeAndValue.CommonName(Asn1String.UTF8("mutated"))
                ),
                attributes = input.attributes,
            )
        }.verifyRejected()
    }

    test("Subject Alternative Name extension mutation after hashed attestation is rejected") {
        val original = X509CertificateExtension(bindingExtensionOid, false, Asn1.OctetString(byteArrayOf(1)))
        hashBindingFixture(extensions = listOf(original)) { input ->
            AttestationHashInput(
                version = input.version,
                subjectName = input.subjectName,
                extensions = listOf(
                    X509CertificateExtension(bindingExtensionOid, false, Asn1.OctetString(byteArrayOf(2)))
                ),
                attributes = input.attributes.filterNot { it.oid == bindingExtensionRequestOid },
            )
        }.verifyRejected()
    }

    test("arbitrary attribute mutation after hashed attestation is rejected") {
        hashBindingFixture { input ->
            AttestationHashInput(
                version = input.version,
                subjectName = input.subjectName,
                attributes = input.attributes + Pkcs10CertificationRequestAttribute(
                    bindingAttributeOid,
                    Asn1String.UTF8("added later").encodeToTlv(),
                ),
            )
        }.verifyRejected()
    }

    test("SHA-256 challenge rejects a proof attested with SHA-384") {
        hashBindingFixture(
            expectedAlgorithm = Digest.SHA256,
            attestedAlgorithm = Digest.SHA384,
        ).verifyRejected()
    }

    test("hash binding succeeds with device name present") {
        hashBindingFixture(
            genericDeviceNameOid = bindingDeviceNameOid,
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(
                    bindingDeviceNameOid,
                    Asn1String.UTF8("Example Device").encodeToTlv(),
                )
            ),
        ).verify().shouldBeInstanceOf<AttestationResponse.Success>()
    }

    test("hash binding succeeds with device name absent") {
        hashBindingFixture(
            genericDeviceNameOid = bindingDeviceNameOid,
        ).verify().shouldBeInstanceOf<AttestationResponse.Success>()
    }

    test("device name mutation after hashed attestation is rejected") {
        hashBindingFixture(
            genericDeviceNameOid = bindingDeviceNameOid,
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(
                    bindingDeviceNameOid,
                    Asn1String.UTF8("Original Device").encodeToTlv(),
                )
            ),
        ) { input ->
            AttestationHashInput(
                version = input.version,
                subjectName = input.subjectName,
                attributes = input.attributes.map {
                    if (it.oid == bindingDeviceNameOid) Pkcs10CertificationRequestAttribute(
                        bindingDeviceNameOid,
                        Asn1String.UTF8("Modified Device").encodeToTlv(),
                    ) else it
                }
            )
        }.verifyRejected()
    }
}
