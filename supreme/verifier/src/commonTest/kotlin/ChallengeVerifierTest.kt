package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import de.infix.testBalloon.framework.core.testSuite
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

val ChallengeVerifierTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 10.minutes)) {

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
        val res1 = cache.validate(nonce)
        res1.shouldBeInstanceOf<ChallengeValidationResult.Success>()
        res1.validatedChallenge shouldBe challenge
        cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
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
        cache.validate(nonce).let { result ->
            cache.validate(twice).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge1
            cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            cache.validate(twice).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }

        cache.store(challenge2)
        cache.validate(twice).let { result ->
            cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge2
            cache.validate(twice).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
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
        cache.validate(nonce).let { result ->
            result.shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            result.reason?.message?.lowercase() shouldContain "multiple"
        }

        cache.store(challenge1)
        cache.validate(nonce).let { result ->
            result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
            result.validatedChallenge shouldBe challenge1
            cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
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
            cache.validate(nonce).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                result.validatedChallenge shouldBe challenge1
                cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            }
        }

        withClue("still valid for 1ms") {
            clock.offsetBy(999.milliseconds)
            cache.store(challenge1)
            cache.validate(nonce).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                result.validatedChallenge shouldBe challenge1
                cache.validate(nonce).shouldBeInstanceOf<ChallengeValidationResult.Failure>()
            }
        }

        withClue("still valid for 0ms, but not expired") {

            cache.store(challenge1)
            clock.offsetBy(1.milliseconds)
            cache.validate(nonce).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Failure>()
                result.reason?.message?.lowercase() shouldContain "no challenge"
            }
        }

        withClue("1ms expired") {
            cache.store(challenge1)
            clock.offsetBy(1.milliseconds)
            cache.validate(nonce).let { result ->
                result.shouldBeInstanceOf<ChallengeValidationResult.Failure>()
                result.reason?.message?.lowercase() shouldContain "no challenge"
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
                    val result = cache.validate(challenge.nonce)
                    result.shouldBeInstanceOf<ChallengeValidationResult.Success>()
                    result.validatedChallenge.nonce shouldBe challenge.nonce
                }
            }

            checkers.joinAll()
        }
    }
}