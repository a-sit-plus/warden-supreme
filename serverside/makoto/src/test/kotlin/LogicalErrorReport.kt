import at.asitplus.attestation.logicalError
import at.asitplus.catchingUnwrapped
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

val LogicalErrorReport by testSuite {
    "sample" {
        val key= KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public
       println(logicalError(key,listOf(Random.nextBytes(1024)),byteArrayOf()).message)
    }
}