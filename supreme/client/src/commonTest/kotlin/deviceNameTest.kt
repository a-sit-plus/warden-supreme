import at.asitplus.attestation.supreme.getDeviceName
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.comparables.shouldBeGreaterThan

val deviceNameTest by testSuite {
    "should return something" {
        getDeviceName().length shouldBeGreaterThan 0
        println("Device name:  ${getDeviceName()}")
    }


}