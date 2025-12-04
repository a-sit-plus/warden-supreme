package at.asitplus.attestation

import at.asitplus.signum.HazardousMaterials
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf

@OptIn(HazardousMaterials::class)
val NoopAttestationServiceTest by testSuite {

    "TestNOOP" {
        NoopAttestationService.verifyAttestation(listOf(), byteArrayOf())
            .shouldBeInstanceOf<AttestationResult.IOS.NOOP>()
        NoopAttestationService.verifyAttestation(listOf(), byteArrayOf()).shouldBeInstanceOf<AttestationResult.IOS>()
        NoopAttestationService.verifyAttestation(listOf(byteArrayOf(), byteArrayOf(), byteArrayOf()), byteArrayOf())
            .shouldBeInstanceOf<AttestationResult.Android>()
        NoopAttestationService.verifyAttestation(listOf(byteArrayOf(), byteArrayOf(), byteArrayOf()), byteArrayOf())
            .shouldBeInstanceOf<AttestationResult.Android.NOOP>()
    }
}