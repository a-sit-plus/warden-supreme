package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.toCryptoPublicKey
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import java.util.*
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val csrKeyPair by lazy { generateRsaKeyPair(1024) }

private fun csrForChallenge(challenge: AttestationChallenge): CertificationRequest {
    val tbsCsr = TbsCertificationRequest(
        subjectName = listOf(RelativeDistinguishedName(challenge.getRdnSerialNumber())),
        publicKey = csrKeyPair.public.toCryptoPublicKey().getOrThrow(),
        attributes = emptyList(),
    )
    return CertificationRequest(
        tbsCsr = tbsCsr,
        signatureAlgorithm = SignatureAlgorithm.RSAwithSHA256andPSSPadding,
        signature = CryptoSignature.RSA(byteArrayOf(0x01)),
    )
}

val ChallengeVerifierTest by matrixSuite(matrixConfig { testConfig = TestConfig.testScope(isEnabled = true, timeout = 10.minutes) }) {

    "once" {
        val nonce = Random.nextBytes(16)
        val clock = FixedTimeClock(Random.nextLong())
        val challenge = AttestationChallenge(
            clock.now(),
            1.seconds,
            null,
            nonce,
            "",
            WardenDefaults.OIDs.ATTESTATION_PROOF
        )
        val cache = InMemoryChallengeCache(clock, Duration.ZERO)

        cache.store(challenge)
        val csr = csrForChallenge(challenge)
        val res1 = cache.validate(csr)
        res1.shouldBeInstanceOf<ChallengeValidationResult.Success>()
        res1.validatedChallenge shouldBe challenge
        cache.validate(csr).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
    }

    "twice" {
        val clock = FixedTimeClock(Random.nextLong())
        val cache = InMemoryChallengeCache(clock, Duration.ZERO)

        val nonce = Random.nextBytes(16)
        val challenge1 = AttestationChallenge(
            clock.now(),
            1.seconds,
            null,
            nonce,
            "",
            WardenDefaults.OIDs.ATTESTATION_PROOF
        )

        val twice = Random.nextBytes(16)
        val challenge2 = AttestationChallenge(
            clock.now(),
            1.seconds,
            null,
            twice,
            "",
            WardenDefaults.OIDs.ATTESTATION_PROOF
        )


        cache.store(challenge1)
        val csr1 = csrForChallenge(challenge1)
        val csr2 = csrForChallenge(challenge2)
        cache.validate(csr1).let { result ->
            cache.validate(csr2).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge1
            cache.validate(csr1).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            cache.validate(csr2).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }

        cache.store(challenge2)
        cache.validate(csr2).let { result ->
            cache.validate(csr1).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge2
            cache.validate(csr2).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            cache.validate(csr1).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }
    }

    "double" {
        val clock = FixedTimeClock(Random.nextLong())
        val cache = InMemoryChallengeCache(clock, Duration.ZERO)

        val nonce = Random.nextBytes(16)
        val challenge1 = AttestationChallenge(
            clock.now(),
            1.seconds,
            null,
            nonce,
            "",
            WardenDefaults.OIDs.ATTESTATION_PROOF
        )


        cache.store(challenge1)
        cache.store(challenge1)
        val csr = csrForChallenge(challenge1)
        cache.validate(csr).let { result ->
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge1
            cache.validate(csr).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }

        cache.store(challenge1)
        cache.validate(csr).let { result ->
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge1
            cache.validate(csr).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }
    }

    "expired" {
        val clock = FixedTimeClock(Random.nextLong())
        val cache = InMemoryChallengeCache(clock, Duration.ZERO)

        val nonce = Random.nextBytes(16)
        val challenge1 = AttestationChallenge(
            clock.now(),
            1.seconds,
            null,
            nonce,
            "",
            WardenDefaults.OIDs.ATTESTATION_PROOF
        )


        withClue("valid") {
            cache.store(challenge1)
            val csr = csrForChallenge(challenge1)
            cache.validate(csr).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                result.validatedChallenge shouldBe challenge1
                cache.validate(csr).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            }
        }

        withClue("still valid for 1ms") {
            clock.offsetBy(999.milliseconds)
            cache.store(challenge1)
            val csr = csrForChallenge(challenge1)
            cache.validate(csr).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                result.validatedChallenge shouldBe challenge1
                cache.validate(csr).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            }
        }

        withClue("still valid for 0ms, but not expired") {

            cache.store(challenge1)
            clock.offsetBy(1.milliseconds)
            val csr = csrForChallenge(challenge1)
            cache.validate(csr).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Failure>()
                result.reason.message?.lowercase() shouldContain "no challenge"
            }
        }

        withClue("1ms expired") {
            cache.store(challenge1)
            clock.offsetBy(1.milliseconds)
            val csr = csrForChallenge(challenge1)
            cache.validate(csr).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Failure>()
                result.reason.message?.lowercase() shouldContain "no challenge"
            }
        }
    }

    "stresstest" - {
        val numberOfNonces = 100_000
        val clock = FixedTimeClock(Random.nextLong())
        val cache = InMemoryChallengeCache(clock, Duration.ZERO)
        val recorded = Channel<AttestationChallenge>(numberOfNonces)
        "Creation" {
            repeat(numberOfNonces) {
                launch {
                    val nonce = WardenDefaults.nonceGenerator()
                    val challenge = AttestationChallenge(
                        clock.now(),
                        1.seconds,
                        null,
                        nonce,
                        "",
                        WardenDefaults.OIDs.ATTESTATION_PROOF
                    )
                    recorded.send(challenge)
                    cache.store(challenge)
                }
            }
        }
        "Validation" {
            val checkers = Stack<Job>()
            repeat(numberOfNonces) {
                checkers += launch {
                    val challenge = recorded.receive()
                    val result = cache.validate(csrForChallenge(challenge))
                    result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                    result.validatedChallenge.nonce shouldBe challenge.nonce
                }
            }

            checkers.joinAll()
        }
    }
}
