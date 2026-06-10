@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import at.asitplus.catching
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlin.text.HexFormat

val AttestationVerifierChallengeTest by matrixSuite {
    "issueChallenge encodes inverse offset" {
        val nonce = Random.Default.nextBytes(16)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge(attestationEndpoint)
        challenge.issuedAt shouldBe (fixedClock.now() - verificationOffset)
    }

    "issueChallenge stores nonce once (property)" {
        val random = Random(1337)
        repeat(25) {
            val nonce = random.nextBytes(random.nextInt(1, 129))

            val attestationJson = loadResourceText(e2eCases.first().attestationResource)
            val verifier = verifierForNonce(nonce)
            val challenge = verifier.issueChallenge(attestationEndpoint)
            val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))
            challenge.nonce.contentEquals(nonce) shouldBe true
            verifier.challengeValidator.validate(csr)
                .shouldBeInstanceOf<ChallengeValidationResult.Success>()
            verifier.challengeValidator.validate(csr)
                .shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }
    }

    "issueChallenge propagates challenge cache overflow" {
        val firstNonce = Random.Default.nextBytes(16)
        val secondNonce = Random.Default.nextBytes(16)
        var first = true
        val verifier = AttestationVerifier(
            makoto = makoto,
            nonceGenerator = suspend {
                if (first) {
                    first = false
                    firstNonce
                } else secondNonce
            },
            challengeValidator = InMemoryChallengeCache(fixedClock, -verificationOffset, maxChallenges = 1),
        )

        verifier.issueChallenge(attestationEndpoint).nonce.contentEquals(firstNonce) shouldBe true
        catching { verifier.issueChallenge(attestationEndpoint) }.exceptionOrNull()
            .shouldBeInstanceOf<InMemoryChallengeCache.ChallengeCacheFullException>()
            .maxChallenges shouldBe 1
    }

    "concurrent verification only consumes a challenge once" {
        val case = e2eCases.first()
        val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge(attestationEndpoint)
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
