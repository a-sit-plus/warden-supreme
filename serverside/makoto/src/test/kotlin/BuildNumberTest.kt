import at.asitplus.attestation.BuildNumber
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.comparables.shouldBeLessThan
import java.util.*
import kotlin.random.Random

class BuildNumberTest : FreeSpec({

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

        withData(testVectors.dropLast(1).mapIndexed { index, s -> index to s }) {
            BuildNumber(it.second) shouldBeLessThan BuildNumber(testVectors[it.first + 1])
        }
    }


})