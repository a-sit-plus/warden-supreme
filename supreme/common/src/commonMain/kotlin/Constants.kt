package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import org.kotlincrypto.random.CryptoRand
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object WardenDefaults {
    /**
     * OIDs used inside the CSR
     */
    @OptIn(ExperimentalUuidApi::class)
    object OIDs {
        /**
         * Default attestation proof attribute OID
         */
        val ATTESTATION_PROOF = ObjectIdentifier(Uuid.parse("3fe0e8a9-4a7a-4cd1-a3cc-93c228908116"))

        /**
         * Default device name attribute OID, can be uses, if desired, but must be manually set
         */
        val DEVICE_NAME = ObjectIdentifier(Uuid.parse("792c51ff-6032-47a3-9c1c-2401be1b6a2f"))
    }

    /**
     * Default, secure random 64-byte nonce generator
     */
    val nonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(64)) }

    object KeyConstraints {
        val p256Signer = at.asitplus.attestation.supreme.KeyConstraints(
            at.asitplus.attestation.supreme.KeyConstraints.AlgorithmParameters.EC(
                curve = ECCurve.SECP_256_R_1,
                allowKeyAgreement = false
            )
        )
    }
}