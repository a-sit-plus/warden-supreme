@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

val AttestationVerifierKeyBindingTest by matrixSuite {
    data(
        "authentication methods",
        listOf(DataAuthentication.Signature, DataAuthentication.Hash(Digest.SHA256)),
        nameFn = { _, value -> value::class.simpleName!! },
    ) test { authentication ->
        val nonce = Random(authentication.hashCode()).nextBytes(16)
        val challengeTemplate = AttestationChallenge(
            issuedAt = fixedClock.now(),
            validity = kotlin.time.Duration.ZERO,
            nonce = nonce,
            attestationEndpoint = attestationEndpoint,
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
        )
        val hashInput = AttestationHashInput(
            subjectName = listOf(RelativeDistinguishedName(challengeTemplate.getRdnSerialNumber())),
        )
        val attestationNonce = when (authentication) {
            DataAuthentication.Signature -> nonce
            is DataAuthentication.Hash -> authentication.algorithm.digest(hashInput.encodeToDer())
        }
        val fake = createFakeAndroidAttestation(
            challenge = attestationNonce,
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
        val challenge = verifier.issueChallenge(attestationEndpoint, dataAuth = authentication)
        val claimedPublicKey = generateEcKeyPair().public.toCryptoPublicKey().getOrThrow()
        val proof = when (authentication) {
            DataAuthentication.Signature -> AttestationProof.Signed(
                createCsrWithSubject(
                    subjectName = listOf(RelativeDistinguishedName(challenge.getRdnSerialNumber())),
                    keyPair = fake.leafKeyPair,
                    attributes = listOf(
                        Pkcs10CertificationRequestAttribute(
                            challenge.proofOID,
                            Asn1String.UTF8(fake.attestationJson()).encodeToTlv(),
                        )
                    ),
                    publicKey = claimedPublicKey,
                )
            )

            is DataAuthentication.Hash -> AttestationProof.Hashed(
                hashInput.toTbsCsr(
                    claimedPublicKey,
                    Pkcs10CertificationRequestAttribute(
                        challenge.proofOID,
                        Asn1String.UTF8(fake.attestationJson()).encodeToTlv(),
                    ),
                ),
            )
        }
        var issuerCalled = false
        var callbackError: PreAttestationError.ClientDataValidation? = null

        val failure = verifier.verifyAttestation(
            proof,
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = {
                issuerCalled = true
                emptyList()
            },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.ATTESTED_PUBLIC_KEY_MISMATCH
        issuerCalled shouldBe false
    }
}
