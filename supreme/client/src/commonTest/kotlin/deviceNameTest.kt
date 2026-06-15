import at.asitplus.attestation.supreme.getDeviceName
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.comparables.shouldBeGreaterThan

val deviceNameTest by matrixSuite {
    "should return something" {
        getDeviceName().length shouldBeGreaterThan 0
        println("Device name:  ${getDeviceName()}")
    }


}