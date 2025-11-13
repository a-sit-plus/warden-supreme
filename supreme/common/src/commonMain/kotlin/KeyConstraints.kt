package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.nativeDigest
import kotlinx.serialization.Serializable
import kotlin.time.Duration

/**
 * Constraints on the key to be created on the client.
 * If properly set, allows for ridiculously hands-free key and attestation statement creation
 */
@Serializable
data class KeyConstraints(

    /**
     * optional algorithm-specific parameters, if any
     */
    val algorithmParameters: AlgorithmParameters,

    /**
     * Key protection requirements
     */
    val keyProtection: KeyProtection? = null
) {
    @Serializable
    sealed class AlgorithmParameters {
        abstract val allowSigning: Boolean
        abstract val digests: Set<Digest>

        @Serializable
        class RSA(
            val keySize: @Serializable(with = BitLengthSerializer::class) BitLength,
            val paddings: Set<RSAPadding> = setOf(RSAPadding.PSS),
            override val digests: Set<Digest> = setOf(Digest.SHA256),
            override val allowSigning: Boolean = true,
            val allowDecrypting: Boolean = false,
        ) : AlgorithmParameters()

        @Serializable
        class EC(
            @Serializable(with = ECCurveSerializer::class)
            val curve: ECCurve = ECCurve.SECP_256_R_1,
            override val digests: Set<@Serializable(with = DigestSerializer::class) Digest> = setOf(curve.nativeDigest),
            override val allowSigning: Boolean = true,
            val allowKeyAgreement: Boolean = false,
        ) : AlgorithmParameters()
    }

    @Serializable
    class KeyProtection(
        val timeout: Duration? = null,
        val deviceLock: Boolean? = null,
        val biometry: Boolean? = null,
        val allowNewBiometricFactors: Boolean? = null,
    )

}