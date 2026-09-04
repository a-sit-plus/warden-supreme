package at.asitplus.attestation.supreme

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.supreme.AttestationProof.Hashed
import at.asitplus.attestation.supreme.SupremeConfiguration.Clock.Fixed
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import examples.javaapi.SupremeVerifierJavaApi
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.time.Instant

val SupremeVerifierJavaApiTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    val javaApiVerifier = JavaAttestationVerifier(
        SupremeConfiguration(
            ios = IosAttestationConfiguration(
                IosAttestationConfiguration.AppData("1234567890", "example.app"),
            ),
            clock = Fixed(Instant.parse("2025-01-10T12:34:56Z")),
        ),
    )


    "issueChallenge" {
        val challenge = SupremeVerifierJavaApi.issueChallenge(javaApiVerifier, "https://example.test/attest")
        challenge.attestationEndpoint shouldBe "https://example.test/attest"
    }

    "verifyWithCallbacks" {
        // A null proof is sufficient here: the call crosses the Java/Kotlin suspend boundary,
        // and the verifier maps the resulting operational failure to a response.
        SupremeVerifierJavaApi.verifyWithCallbacks(
            javaApiVerifier, Hashed(
                TbsCertificationRequest(
                    subjectName = emptyList(),
                    publicKey = generateRsaKeyPair(1024).public.toCryptoPublicKey().getOrThrow(),
                    attributes = emptyList(),
                ),
            )
        ).shouldBeInstanceOf<AttestationResponse.Failure>()
            .kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }


}
