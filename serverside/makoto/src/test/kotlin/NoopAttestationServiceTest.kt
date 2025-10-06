package at.asitplus.attestation

import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.types.shouldBeInstanceOf

class NoopAttestationServiceTest : AnnotationSpec() {

    @Test
    fun TestNOOP() {
        NoopAttestationService.verifyAttestation(listOf(), byteArrayOf()).shouldBeInstanceOf<AttestationResult.IOS.NOOP>()
        NoopAttestationService.verifyAttestation(listOf(), byteArrayOf()).shouldBeInstanceOf<AttestationResult.IOS>()
        NoopAttestationService.verifyAttestation(listOf(byteArrayOf(), byteArrayOf(), byteArrayOf()), byteArrayOf())
            .shouldBeInstanceOf<AttestationResult.Android>()
        NoopAttestationService.verifyAttestation(listOf(byteArrayOf(), byteArrayOf(), byteArrayOf()), byteArrayOf())
            .shouldBeInstanceOf<AttestationResult.Android.NOOP>()
    }
}