@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.text.HexFormat

val AttestationVerifierE2EAttestationTest by testSuite {
    e2eCases.forEach { case ->
        "e2e rejects invalid CSR signature (${case.name})" {
            val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
            val verifier = verifierForNonce(nonce)
            val challenge = verifier.issueChallenge("https://example.invalid/attest")
            val attestationJson = loadResourceText(case.attestationResource)
            val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))

            val preErrors = mutableListOf<PreAttestationError>()
            val attErrors = mutableListOf<AttestationResult.Error>()
            val debugInfos = mutableListOf<WardenDebugAttestationStatement>()
            val response = verifier.verifyAttestation(
                csr,
                onPreAttestationError = {
                    preErrors += this
                    "pre"
                },
                onAttestationError = { debugInfo ->
                    attErrors += this
                    debugInfos += debugInfo
                    "att"
                },
                certificateIssuer = { emptyList() }
            )
            response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                withClue(failure.explanation ?: "no explanation") {
                    failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
                }
            }

            preErrors shouldHaveSize 0
            attErrors shouldHaveSize 1
            debugInfos shouldHaveSize 1
            withClue("expected debug info to carry the issued nonce") {
                debugInfos.single().challenge?.contentEquals(nonce) shouldBe true
            }
        }
    }
}
