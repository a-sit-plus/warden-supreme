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

private val hashAuthentication = DataAuthentication.Hash(Digest.SHA256)

private suspend fun mismatchedAuthenticationProof(
    challengeAuthentication: DataAuthentication,
    responseAuthentication: DataAuthentication,
): Pair<AttestationVerifier, AttestationProof> {
    val nonce = Random(challengeAuthentication.hashCode()).nextBytes(16)
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
    val attestationNonce = when (responseAuthentication) {
        DataAuthentication.Signature -> nonce
        is DataAuthentication.Hash ->
            responseAuthentication.algorithm.digest(hashInput.encodeToDer())
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
    val challenge = verifier.issueChallenge(
        attestationEndpoint,
        keyConstraints = WardenDefaults.KeyConstraints.p256Signer,
        dataAuth = challengeAuthentication,
    )

    val proof = when (responseAuthentication) {
        DataAuthentication.Signature ->
            AttestationProof.Signed(createCsr(challenge, fake.attestationJson(), fake.leafKeyPair))

        is DataAuthentication.Hash -> AttestationProof.Hashed(
            hashInput.toTbsCsr(
                fake.leafKeyPair.public.toCryptoPublicKey().getOrThrow(),
                Pkcs10CertificationRequestAttribute(
                    challenge.proofOID,
                    Asn1String.UTF8(fake.attestationJson()).encodeToTlv(),
                ),
            ),
        )
    }
    return verifier to proof
}

val AttestationVerifierAuthenticationMismatchTest by matrixSuite {
    suspend fun verifyMismatch(
        verifier: AttestationVerifier,
        proof: AttestationProof,
    ) {
        var callbackError: PreAttestationError.ClientDataValidation? = null
        val failure = verifier.verifyAttestation(
            proof,
            onPreAttestationError = {
                callbackError = shouldBeInstanceOf<PreAttestationError.ClientDataValidation>()
                "callback"
            },
            certificateIssuer = { emptyList() },
        ).shouldBeInstanceOf<AttestationResponse.Failure>()

        failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
        failure.explanation shouldBe "callback"
        callbackError?.reason shouldBe
            PreAttestationError.ClientDataValidation.Reason.AUTHENTICATION_METHOD_MISMATCH
    }

    test("hash challenge rejects a self-consistent signed CSR response") {
        val (verifier, proof) = mismatchedAuthenticationProof(
            challengeAuthentication = hashAuthentication,
            responseAuthentication = DataAuthentication.Signature,
        )

        verifyMismatch(verifier, proof)
    }

    test("signature challenge rejects a self-consistent hashed TBS CSR response") {
        val (verifier, proof) = mismatchedAuthenticationProof(
            challengeAuthentication = DataAuthentication.Signature,
            responseAuthentication = hashAuthentication,
        )

        verifyMismatch(verifier, proof)
    }
}
