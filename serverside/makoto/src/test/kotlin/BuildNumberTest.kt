import at.asitplus.attestation.BuildNumber
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.comparables.shouldBeLessThan
import java.util.*
import kotlin.random.Random

val BuildNumberTest by matrixSuite {

    "presorted" - {
        val buildTrains = List(50) { it }

        val minorVer = listOf(
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z"
        )
        val buildNumber = TreeSet<Int>().apply {
            repeat(50) {
                add(Random.nextInt(0, Int.MAX_VALUE))
            }
        }

        val masteringNumber = "qwertzuioplkjhgfdssayxcvbnm".toCharArray().sorted().map { it.toString() }

        val testVectors = mutableListOf<String>().apply {
            buildTrains.forEach { train ->
                minorVer.forEach { minor ->
                    buildNumber.forEach { buildNum ->
                        this.add(train.toString() + minor + buildNum + if (buildNum.mod(3) != 0) masteringNumber.random() else "")
                    }
                }
            }
        }

        compact("presorted build numbers") {
            report = CompactReport.FailuresOnly
        } - {
            data(
            testVectors.dropLast(1).mapIndexed { index, s -> index to s },
            ) test {
                BuildNumber(it.second) shouldBeLessThan BuildNumber(testVectors[it.first + 1])
            }
        }
    }
}
