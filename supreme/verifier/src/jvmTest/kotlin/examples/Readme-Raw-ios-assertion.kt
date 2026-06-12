package examples.docs

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.CanonicalIosAttestation
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.ValidatedAttestationSerializer
import at.asitplus.attestation.canonicalize
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import kotlinx.serialization.json.Json

/**
 * iOS-only assertion validation with a previously stored [ValidatedAttestation].
 *
 * This mirrors the raw integration flow:
 * 1. Verify App Attestation
 * 2. Persist ValidatedAttestation
 * 3. Load it later
 * 4. Verify a fresh assertion
 */
object RawIosAssertionExample {

    fun verifyAssertionWithStoredAttestation(
        makoto: Makoto,
        attestationObject: ByteArray,
        challengeAtRegistration: ByteArray,
        assertionFromDevice: ByteArray,
        expectedChallenge: ByteArray,
        previousCounter: Long,
    ): Pair<Result<Assertion>, Result<Assertion>> { val json = Json {}


        val registration = /*(1)!*/makoto.ios.verifyAppAttestation(attestationObject, challengeAtRegistration)
        val verified = /*(2)!*/registration as AttestationResult.IOS.Verified

        // JSON persistence using ValidatedAttestationSerializer
        val storedJson: String = /*(3)!*/json.encodeToString(ValidatedAttestationSerializer, verified.attestation)
        val validatedAttestationFromJson: ValidatedAttestation =
            json.decodeFromString(ValidatedAttestationSerializer, storedJson)

        val assertionResultFromJson = /*(4)!*/makoto.ios.verifyAssertion(
            validatedAttestation = validatedAttestationFromJson,
            assertion = assertionFromDevice,
            expectedChallenge = expectedChallenge,
            validCounters = /*(5)!*/(previousCounter - 1)..previousCounter
        )

        // ASN.1/DER persistence using CanonicalIosAttestation is also possible
        val storedDer: ByteArray = /*(6)!*/verified.attestation.canonicalize().encodeToDer()
        val validatedAttestationFromDer =
            CanonicalIosAttestation.decodeFromDer(storedDer).toValidatedAttestation()

        val assertionResultFromDer = makoto.ios.verifyAssertion(
            validatedAttestation = validatedAttestationFromDer,
            assertion = assertionFromDevice,
            expectedChallenge = expectedChallenge,
            validCounters = (previousCounter - 1)..previousCounter
        )





        return assertionResultFromJson to assertionResultFromDer
    }
}
