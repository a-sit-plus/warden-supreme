package at.asitplus.attestation

import JavaInteropTest
import at.asitplus.testballoon.matrix.*

val JavaInteropTestRunner by matrixSuite {

    "testDefaults" { JavaInteropTest.testDefaults() }
    "testAttestationCallsJavaFriendliness" { JavaInteropTest.testAttestationCallsJavaFriendliness() }

}