package at.asitplus.attestation.supreme

import at.asitplus.attestation.supreme.AttestationProof.Hashed
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import examples.javaapi.SupremeVerifierJavaApi
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val SupremeVerifierJavaApiTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    val javaApiVerifier = SupremeVerifierJavaApi.newVerifier()


    "issueChallenge" {
        val challenge = SupremeVerifierJavaApi.issueChallenge(javaApiVerifier, "https://example.test/attest").join()
        challenge.attestationEndpoint shouldBe "https://example.test/attest"
    }

    "verifyWithCallbacks" {
        // A structurally incomplete proof is sufficient to exercise the Java callback boundary.
        SupremeVerifierJavaApi.verify(
            javaApiVerifier, Hashed(
                TbsCertificationRequest(
                    subjectName = emptyList(),
                    publicKey = generateRsaKeyPair(1024).public.toCryptoPublicKey().getOrThrow(),
                    attributes = emptyList(),
                ),
            )
        ).join().shouldBeInstanceOf<AttestationResponse.Failure>()
            .kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }


}
