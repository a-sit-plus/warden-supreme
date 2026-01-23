@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlin.text.HexFormat

val AttestationVerifierChallengeTest by testSuite {
    "issueChallenge encodes inverse offset" {
        val nonce = Random.Default.nextBytes(16)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        challenge.issuedAt shouldBe (fixedClock.now() - verificationOffset)
    }

    "issueChallenge stores nonce once (property)" {
        val random = Random(1337)
        repeat(25) {
            val nonce = random.nextBytes(random.nextInt(1, 129))
            val verifier = verifierForNonce(nonce)
            val challenge = verifier.issueChallenge("https://example.invalid/attest")
            challenge.nonce.contentEquals(nonce) shouldBe true
            verifier.challengeValidator.validate(nonce)
                .shouldBeInstanceOf<ChallengeValidationResult.Success>()
            verifier.challengeValidator.validate(nonce)
                .shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }
    }

    "concurrent verification only consumes a challenge once" {
        val case = e2eCases.first()
        val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val attestationJson = loadResourceText(case.attestationResource)
        val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))

        val issuerCalls = AtomicInteger(0)
        val results = (1..20).map {
            async {
                verifier.verifyAttestation(
                    csr,
                    certificateIssuer = {
                        issuerCalls.incrementAndGet()
                        emptyList()
                    },
                )
            }
        }.awaitAll()

        val nonContent = results.filterNot { it is AttestationResponse.Failure && it.kind == AttestationResponse.Failure.Type.CONTENT }
        withClue("expected only one non-CONTENT result") {
            nonContent shouldHaveSize 1
        }
        withClue("issuer should run at most once") {
            (issuerCalls.get() <= 1) shouldBe true
        }
    }
}
