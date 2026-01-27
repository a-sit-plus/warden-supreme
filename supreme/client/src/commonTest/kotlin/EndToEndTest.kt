import at.asitplus.attestation.supreme.*
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.test.Target
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.datetime.LocalDate
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"

val ALIAS = "ALIAS"

val EndToEndTest by testSuite {
    //This test lives here due to IDEA not recognizing androidDevicTest sources being wired to commonTest
    //to not make ios fail, we guard it here
    if (Target.current == Target.ANDROID_ART) {

        test("endToEnd") {
            PlatformSigningProvider.deleteSigningKey(ALIAS)
            val client = AttestationClient(HttpClient(), FixedTimeClock(2025u,1u,10u))

            val result = client.performAttestationFlow(ALIAS,Url(ENDPOINT_CHALLENGE))
            val clue =
                if (result is AttestationResponse.Failure)
                    result.kind.name + ": " + (result.explanation ?: "FAIL")
                else ""
            withClue(clue) {
                result.shouldBeInstanceOf<AttestationResponse.Success>()
                withClue("Cert leaf pub key is the original attested key") {
                    result.certificateChain.leaf.decodedPublicKey.getOrThrow() shouldBe PlatformSigningProvider.getSignerForKey(
                        ALIAS
                    ).getOrThrow().publicKey
                }
            }

        }


        test("shutdown") {
            HttpClient().get(ENDPOINT_SHUTDOWN)
        }
    } else test("NOOP") {

    }
}

private class FixedTimeClock(private var epochMilliseconds: Long) : Clock {
    constructor(instant: Instant) : this(instant.toEpochMilliseconds())
    constructor(yyyy: UInt, mm: UInt, dd: UInt) : this(
        LocalDate(yyyy.toInt(), mm.toInt(), dd.toInt()).toEpochDays().days.inWholeMilliseconds
    )

    fun offsetBy(duration: Duration) {
        epochMilliseconds += duration.inWholeMilliseconds
    }

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)
}