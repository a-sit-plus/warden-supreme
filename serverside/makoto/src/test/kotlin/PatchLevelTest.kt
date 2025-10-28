import at.asitplus.attestation.android.PatchLevel
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import java.time.Month
import java.time.YearMonth

private data class YmTestData(val year: Int, val month: Int, val javaMonth: Month)

val PatchLevelTest by testSuite {

    "conversion" - {
        withData(
            YmTestData(2025, 1, Month.JANUARY),
            YmTestData(2025, 2, Month.FEBRUARY),
            YmTestData(2025, 3, Month.MARCH),
            YmTestData(2025, 4, Month.APRIL),
            YmTestData(2025, 5, Month.MAY),
            YmTestData(2025, 6, Month.JUNE),
            YmTestData(2025, 7, Month.JULY),
            YmTestData(2025, 8, Month.AUGUST),
            YmTestData(2025, 9, Month.SEPTEMBER),
            YmTestData(2025, 10, Month.OCTOBER),
            YmTestData(2025, 11, Month.NOVEMBER),
            YmTestData(2025, 12, Month.DECEMBER),
        ) { (year, month, javaMonth) ->
            val patchLevel = PatchLevel(year, month)
            val ym = YearMonth.of(patchLevel.year, patchLevel.month)

            ym.year shouldBe year
            ym.month.value shouldBe month
            ym.month shouldBe javaMonth

            patchLevel.asYearMonth shouldBe ym

            PatchLevel.fromSingleInt(patchLevel.asSingleInt, patchLevel.maxFuturePatchLevelMonths) shouldBe patchLevel

            PatchLevel(patchLevel.asYearMonth, patchLevel.maxFuturePatchLevelMonths) shouldBe patchLevel
        }
    }

    "parserCheck" - {
        "illegal" - {
            withData(
                "0" to "0",
                "0" to "13",
                "0" to "99",
                "0" to "100",
            ) { (y, m) ->
                val singleInt = "$y$m".toInt()
                shouldThrow<IllegalArgumentException> { PatchLevel.fromSingleInt(singleInt) }
            }
        }

        "legal" - {
            withData(
                "0" to "1",
                "-0" to "1", /*same as above*/
                "-1" to "12",
                "-999" to "01",
                "9999999" to "01",
            ) { (y, m) ->
                val singleInt = "$y$m".toInt()
                val pl = PatchLevel.fromSingleInt(singleInt)
                pl.year shouldBe y.toInt()
                pl.month shouldBe m.toInt()
            }
        }


    }
}