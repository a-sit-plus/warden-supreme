package docs.config

import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.ChallengeValidator
import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.attestation.supreme.KeyConstraints.AlgorithmParameters
import at.asitplus.attestation.supreme.KeyConstraints.KeyProtection
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.nativeDigest
import docs.config.minimal.makoto
import org.kotlincrypto.random.CryptoRand
import kotlin.time.Duration.Companion.seconds

val rdbmsBacked: ChallengeValidator = TODO()
var serviceSpecificOID = WardenDefaults.OIDs.ATTESTATION_PROOF

val verifier = AttestationVerifier(
    makoto = makoto,
 /*(1)!*/attestationProofOID = serviceSpecificOID, //DEFAULT
 /*(2)!*/includeGenericDeviceName = false, //true by default
 /*(3)!*/defaultKeyConstraints = KeyConstraints(
        algorithmParameters = AlgorithmParameters.EC(
            curve = ECCurve.SECP_256_R_1,
            digests = setOf(ECCurve.SECP_256_R_1.nativeDigest),
            allowSigning = true, //DEFAULT
            allowKeyAgreement = false //DEFAULT
        ),
 /*(4)!*/keyProtection = KeyProtection(
            timeout = 30.seconds,
            deviceLock = false,
            biometry = true,
            allowNewBiometricFactors = false
        )
    ),
    nonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(/*(5)!*/128)) },
 /*(6)!*/challengeValidator = rdbmsBacked
)