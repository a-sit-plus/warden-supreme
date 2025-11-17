package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.catchingUnwrapped
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import ch.veehait.devicecheck.appattest.receipt.ReceiptValidator
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

val TimeOffsetTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 15.minutes)) {

    val rands = Array<Duration?>(10) {
        //There are limits to durations, and this will mostly be infinities, but it caught an Android config bug, so it stays
        catchingUnwrapped { Random.nextInt().seconds }.getOrNull()
    } + Array<Duration?>(10) {
        //long durations
        Random.nextInt().seconds
    } + Array<Duration?>(10) {
        //shorter ones
        Random.nextInt().milliseconds
    } + Array<Duration?>(10) {
        //shorter ones
        Random.nextInt().nanoseconds
    }
    "makoto vs bare" - {
        withData(
            5.minutes, Duration.ZERO, null as Duration?, *rands,
        ) - { offset ->

            //we only have seconds precision here
            withData(
                *Array<Duration?>(50) { Random.nextInt(0, Int.MAX_VALUE).seconds },
            ) - { validity ->

                val expectedValidity =
                    validity
                        ?: (ReceiptValidator.APPLE_RECOMMENDED_MAX_AGE.toKotlinDuration() + Makoto.DEFAULT_TIME_OFFSET)

                val expectedOffset = offset ?: Makoto.DEFAULT_TIME_OFFSET
                val clk = FixedTimeClock(0)


                val androidAttestationConfiguration = if (validity != null) AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        "foo",
                        listOf(byteArrayOf())
                    ),
                    attestationStatementValiditySeconds = expectedValidity.inWholeSeconds
                ) else AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        "foo",
                        listOf(byteArrayOf())
                    )
                )
                val iosAttestationConfiguration = if (validity != null) IosAttestationConfiguration(
                    IosAttestationConfiguration.AppData(
                        "1234567890",
                        "baz"
                    ),
                    attestationStatementValiditySeconds = expectedValidity.inWholeSeconds
                ) else IosAttestationConfiguration(
                    IosAttestationConfiguration.AppData(
                        "1234567890",
                        "baz"
                    )
                )


                val makoto = if (offset != null) Makoto(
                    androidAttestationConfiguration,
                    iosAttestationConfiguration,
                    clock = clk,
                    verificationTimeOffset = expectedOffset
                )
                else Makoto(
                    androidAttestationConfiguration,
                    iosAttestationConfiguration,
                    clock = clk,
                )

                val expectedIssuedAt = clk.now() - makoto.verificationTimeOffset


                //we verify makoto functionality here and not separately, as the verifier is tightly tied to it
                //hence, it makes sense to contain these tests here
                "makoto config checks" {
                    withClue("Offset for $offset") { makoto.verificationTimeOffset shouldBe expectedOffset }
                    withClue("Validity for $validity") { makoto.shortestValidityDuration shouldBe expectedValidity}
                }


                withData(
                    mapOf(
                        "makoto" to AttestationVerifier(makoto),
                        "bare" to if (offset == null) AttestationVerifier(
                            androidAttestationConfiguration,
                            iosAttestationConfiguration,
                            clock = clk,
                        ) else AttestationVerifier(
                            androidAttestationConfiguration,
                            iosAttestationConfiguration,
                            clock = clk, verificationTimeOffset = expectedOffset
                        )
                    )
                ) { verifier ->
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
}