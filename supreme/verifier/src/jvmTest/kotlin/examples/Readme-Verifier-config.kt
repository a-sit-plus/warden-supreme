package examples.docs.config.supreme

import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.AttestationChallengeValidator
import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.attestation.supreme.KeyConstraints.AlgorithmParameters
import at.asitplus.attestation.supreme.KeyConstraints.KeyProtection
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.nativeDigest
import examples.docs.config.minimal.makoto
import org.kotlincrypto.random.CryptoRand
import kotlin.time.Duration.Companion.seconds

val redisBacked: AttestationChallengeValidator = TODO()
val serviceSpecificOID = WardenDefaults.OIDs.ATTESTATION_PROOF
// UUID-derived example OID (UUID e4da8413-46ae-4f0f-88f5-c7325b5850b0)
val customerAttributesOID = ObjectIdentifier("2.25.304198582559398858370235454530489176240")






// --8<-- [start:verifier-config-supreme]
val configuration = SupremeConfiguration(
 /*(1)!*/android = makoto.androidAttestationConfiguration!!,
    ios = makoto.iosAttestationConfiguration!!,
 /*(2)!*/clock = SupremeConfiguration.Clock.System,
 /*(3)!*/attestationProofOID = serviceSpecificOID, //override default
 /*(4)!*/genericDeviceNameOID = null, //WardenDefaults.OIDs.DEVICE_NAME by default
 /*(5)!*/defaultKeyConstraints = KeyConstraints(
        algorithmParameters = AlgorithmParameters.EC(
            curve = ECCurve.SECP_256_R_1,
            digests = setOf(ECCurve.SECP_256_R_1.nativeDigest),
            allowKeyAgreement = false //DEFAULT
        ),
 /*(6)!*/keyProtection = KeyProtection(
            timeout = 30.seconds,
            deviceLock = false,
            biometry = true,
            allowNewBiometricFactors = false,
        )
    ),
 /*(7)!*/toBeAttestedAttributes = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
        customerAttributesOID,
        listOf(
            AttestationChallenge.AttributeAttestationDescriptor("accountId", PrimitiveType.STRING),
            AttestationChallenge.AttributeAttestationDescriptor("riskScore", PrimitiveType.INT, required = false),
        ),
    ),
 /*(8)!*/dataAuth = DataAuthentication.Hash(Digest.SHA256),
)

val verifier = AttestationVerifier(
    configuration,
 /*(9)!*/nonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(/*(10)!*/128)) },
) {/*(11)!*/clock, offset -> redisBacked }
// --8<-- [end:verifier-config-supreme]
