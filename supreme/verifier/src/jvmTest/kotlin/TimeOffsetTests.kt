package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.catchingUnwrapped
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.frequency
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.withEdgecases
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

private data class TimeOffsetCase(val offset: Duration?, val validity: Duration?)

private val offsetArb: Arb<Duration?> = Arb.frequency(
    // This broad conversion caught an Android configuration bug, so keep it alongside the finer-grained durations.
    10 to Arb.int().map { catchingUnwrapped { it.seconds }.getOrNull() },
    10 to Arb.int().map { it.seconds },
    10 to Arb.int().map { it.milliseconds },
    10 to Arb.int().map { it.nanoseconds },
).withEdgecases(5.minutes, Duration.ZERO, null)

private val validityArb: Arb<Duration?> = Arb.int(0..Int.MAX_VALUE).map { it.seconds }
private val timeOffsetCaseArb = Arb.bind(offsetArb, validityArb, ::TimeOffsetCase)

val TimeOffsetTest by matrixSuite(matrixConfig { testConfig = TestConfig.testScope(isEnabled = true, timeout = 15.minutes) }) {
    compact("makoto vs bare")- {
        property(timeOffsetCaseArb, iterations = 2150) test { (offset, validity) ->
            val expectedValidity =
                validity ?: (ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE.toKotlinDuration() + Makoto.DEFAULT_TIME_OFFSET)
            val expectedOffset = offset ?: Makoto.DEFAULT_TIME_OFFSET

            val clk = FixedTimeClock(0)
            val clkConfig = object : SupremeConfiguration.Clock {
                override val timeSource: Clock
                    get() = clk
            }

            val androidAttestationConfiguration = if (validity != null) AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("foo", setOf(byteArrayOf())),
                attestationStatementValiditySeconds = expectedValidity.inWholeSeconds,
            ) else AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("foo", setOf(byteArrayOf())),
            )
            val iosAttestationConfiguration = if (validity != null) IosAttestationConfiguration(
                IosAttestationConfiguration.AppData("1234567890", "baz"),
                attestationStatementValiditySeconds = expectedValidity.inWholeSeconds,
            ) else IosAttestationConfiguration(
                IosAttestationConfiguration.AppData("1234567890", "baz"),
            )

            val makoto = if (offset != null) Makoto(
                androidAttestationConfiguration,
                iosAttestationConfiguration,
                clock = clk,
                verificationTimeOffset = expectedOffset,
            ) else Makoto(
                androidAttestationConfiguration,
                iosAttestationConfiguration,
                clock = clk,
            )
            val expectedIssuedAt = clk.now() - makoto.verificationTimeOffset

            withClue("Offset for $offset") { makoto.verificationTimeOffset shouldBe expectedOffset }
            withClue("Validity for $validity") { makoto.shortestValidityDuration shouldBe expectedValidity }

            listOf(
                AttestationVerifier(makoto),
                AttestationVerifier(
                    SupremeConfiguration(
                        androidAttestationConfiguration,
                        iosAttestationConfiguration,
                        clkConfig,
                        verificationTimeOffset = expectedOffset,
                    )
                ),
            ).forEach { verifier ->
                verifier.nonceValidity shouldBe expectedValidity
                verifier.issueChallenge("").let {
                    withClue("Issued at") { it.issuedAt shouldBe expectedIssuedAt }
                    withClue("Validity") { it.validity shouldBe expectedValidity }
                    withClue("Valid until") { it.validUntil shouldBe expectedIssuedAt + expectedValidity }
                }
            }
        }
    }
}
