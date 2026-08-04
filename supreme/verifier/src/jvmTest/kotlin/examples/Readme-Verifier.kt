package examples.docs.config

import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.ChallengeValidator
import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.KeyConstraints.AlgorithmParameters
import at.asitplus.attestation.supreme.KeyConstraints.KeyProtection
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.nativeDigest
import examples.docs.config.minimal.makoto
import org.kotlincrypto.random.CryptoRand
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

val redisBacked: ChallengeValidator = TODO()
val serviceSpecificOID = WardenDefaults.OIDs.ATTESTATION_PROOF
// UUID-derived example OID (UUID e4da8413-46ae-4f0f-88f5-c7325b5850b0)
val customerAttributesOID = ObjectIdentifier("2.25.304198582559398858370235454530489176240")






val verifier = AttestationVerifier(
    makoto = makoto,
 /*(1)!*/attestationProofOID = serviceSpecificOID, //override default
 /*(2)!*/genericDeviceNameOID = null, //WardenDefaults.OIDs.DEVICE_NAME by default
 /*(3)!*/defaultKeyConstraints = KeyConstraints(
        algorithmParameters = AlgorithmParameters.EC(
            curve = ECCurve.SECP_256_R_1,
            digests = setOf(ECCurve.SECP_256_R_1.nativeDigest),
            allowKeyAgreement = false //DEFAULT
        ),
 /*(4)!*/keyProtection = KeyProtection(
            timeout = 30.seconds,
            deviceLock = false,
            biometry = true,
            allowNewBiometricFactors = false,
        )
    ),
    nonceValidity = 5.minutes, //DEFAULT
    nonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(/*(5)!*/128)) },
 /*(6)!*/challengeValidator = redisBacked,
 /*(7)!*/attestableAttributes = AttestationChallenge.AttestableAttributes(
        customerAttributesOID,
        listOf(
            AttestationChallenge.ToBeAttestedAttribute("accountId", PrimitiveType.STRING),
            AttestationChallenge.ToBeAttestedAttribute("riskScore", PrimitiveType.INT, required = false),
        ),
    ),
 /*(8)!*/dataAuth = DataAuthentication.Hash(Digest.SHA256),
)
