package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

val TimeOffsetTest by testSuite {

    "makoto vs bare" - {
        val clk = FixedTimeClock(0)
        val offset = Duration.ZERO

        val makoto = Makoto(
             AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData(
                    "foo",
                    listOf(byteArrayOf())
                )
            ),
              IosAttestationConfiguration(
                IosAttestationConfiguration.AppData(
                    "1234567890",
                    "baz"
                )
            ),
            clock = clk
        )

        //we verify makoto functionality here and not separately, as the verifier is tightly tied to it
        //hence, it makes sense to contain these tests here
         "makoto" {
             makoto.verificationTimeOffset shouldBe Makoto.DEFAULT_TIME_OFFSET
         }
        val verifier = AttestationVerifier(makoto)
        "verifier" {
            verifier.issueChallenge("").issuedAt shouldBe clk.now() - makoto.verificationTimeOffset
        }




    }
}