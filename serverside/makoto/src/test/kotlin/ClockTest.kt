import at.asitplus.attestation.toKotlinClock
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import java.time.Clock
import java.time.Instant
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

@OptIn(ExperimentalTime::class)
val ClockTest by matrixSuite {

    "java to kotlin" {
        val javaClock = Clock.fixed(Instant.parse("2023-01-01T12:00:00Z"), Clock.systemUTC().zone)

        javaClock.instant().toKotlinInstant() shouldBe javaClock.toKotlinClock().now()
    }
}