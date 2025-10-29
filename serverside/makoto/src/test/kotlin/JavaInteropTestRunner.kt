package at.asitplus.attestation

import JavaInteropTest
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite

val JavaInteropTestRunner by testSuite {

    "testDefaults" { JavaInteropTest.testDefaults() }
    "testAttestationCallsJavaFriendliness" { JavaInteropTest.testAttestationCallsJavaFriendliness() }

}