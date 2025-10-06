package at.asitplus.attestation

import JavaInteropTest
import io.kotest.core.spec.style.AnnotationSpec

class JavaInteropTestRunner : AnnotationSpec() {
    @Test
    fun testDefaults() = JavaInteropTest.testDefaults()
    @Test
    fun testAttestationCallsJavaFriendliness() = JavaInteropTest.testAttestationCallsJavaFriendliness()

}