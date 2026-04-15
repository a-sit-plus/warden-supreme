package at.asitplus.attestation

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite

val JavaSpringInteropBridgeTest by testSuite {
    "java can call spring config loaders through Class overloads" {
        JavaSpringInteropAssertions.run()
    }
}
