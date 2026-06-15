package at.asitplus.attestation

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.types.shouldBeInstanceOf

@OptIn(DisabledAttestation::class)
val NoopAttestationServiceTest by matrixSuite {

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