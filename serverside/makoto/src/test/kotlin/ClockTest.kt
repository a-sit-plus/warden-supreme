import at.asitplus.attestation.toKotlinClock
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import java.time.Clock
import java.time.Instant
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

@OptIn(ExperimentalTime::class)
val ClockTest by testSuite {

    "java to kotlin" {
        val javaClock = Clock.fixed(Instant.parse("2023-01-01T12:00:00Z"), Clock.systemUTC().zone)

        javaClock.instant().toKotlinInstant() shouldBe javaClock.toKotlinClock().now()
    }
}