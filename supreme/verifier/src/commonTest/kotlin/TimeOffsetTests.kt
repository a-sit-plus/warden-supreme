package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.catchingUnwrapped
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

val TimeOffsetTest by testSuite {

    val rands = Array<Duration?>(500) {
        //There are limits to durations, and this will mostly be infinities, but it caught an Android config bug, so it stays
        catchingUnwrapped { Random.nextInt().seconds }.getOrNull()
    } + Array<Duration?>(500) {
        //long durations
        Random.nextInt().seconds
    } + Array<Duration?>(500) {
        //shorter ones
        Random.nextInt().milliseconds
    } + Array<Duration?>(500) {
        //shorter ones
        Random.nextInt().nanoseconds
    }
    "makoto vs bare" - {
        withData(
            5.minutes, Duration.ZERO, null as Duration?,
            *rands
        ) - { validity ->

            val expectedOffset = validity ?: Makoto.DEFAULT_TIME_OFFSET
            val clk = FixedTimeClock(0)


            var androidAttestationConfiguration = AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData(
                    "foo",
                    listOf(byteArrayOf())
                )
            )
            var iosAttestationConfiguration = IosAttestationConfiguration(
                IosAttestationConfiguration.AppData(
                    "1234567890",
                    "baz"
                )
            )
            val makoto = if (validity != null) Makoto(
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

            //we verify makoto functionality here and not separately, as the verifier is tightly tied to it
            //hence, it makes sense to contain these tests here
            val expectedValidity = clk.now() - makoto.verificationTimeOffset
            "makoto" {
                makoto.verificationTimeOffset shouldBe expectedOffset
                val verifier = AttestationVerifier(makoto)
                verifier.issueChallenge("").issuedAt shouldBe expectedValidity
            }
            "bare" {
                val verifier =
                    if (validity == null) AttestationVerifier(
                        androidAttestationConfiguration,
                        iosAttestationConfiguration,
                        clock = clk,
                    ) else AttestationVerifier(
                        androidAttestationConfiguration,
                        iosAttestationConfiguration,
                        clock = clk, verificationTimeOffset = expectedOffset
                    )

                verifier.issueChallenge("").issuedAt shouldBe expectedValidity
            }


        }

    }
}