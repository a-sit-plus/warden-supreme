package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.nativeDigest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

/**
 * Constraints on the key to be created on the client.
 * If properly set, allows for ridiculously hands-free key and attestation statement creation
 *
 * **Note that not all clients can enforce all constraints!**
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
        @SerialName("RSA")
        class RSA(
            val keySize: @Serializable(with = BitLengthSerializer::class) BitLength,
            val paddings: Set<RSAPadding> = setOf(RSAPadding.PSS),
            override val digests: Set<Digest> = setOf(Digest.SHA256),
            val allowDecrypting: Boolean = false,
        ) : AlgorithmParameters() {
            //must be true as of now, because we require signing for proof of possession
            override val allowSigning: Boolean = true
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is RSA) return false
                if (!super.equals(other)) return false

                if (allowSigning != other.allowSigning) return false
                if (allowDecrypting != other.allowDecrypting) return false
                if (keySize != other.keySize) return false
                if (paddings != other.paddings) return false
                if (digests != other.digests) return false

                return true
            }

            override fun hashCode(): Int {
                var result = super.hashCode()
                result = 31 * result + allowSigning.hashCode()
                result = 31 * result + allowDecrypting.hashCode()
                result = 31 * result + keySize.hashCode()
                result = 31 * result + paddings.hashCode()
                result = 31 * result + digests.hashCode()
                return result
            }
        }

        @Serializable
        @SerialName("EC")
        class EC(
            @Serializable(with = ECCurveSerializer::class)
            val curve: ECCurve = ECCurve.SECP_256_R_1,
            override val digests: Set<@Serializable(with = DigestSerializer::class) Digest> = setOf(curve.nativeDigest),
            val allowKeyAgreement: Boolean = false,
        ) : AlgorithmParameters() {
            //must be true as of now, because we require signing for proof of possession
            override val allowSigning: Boolean = true
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is EC) return false
                if (!super.equals(other)) return false

                if (allowSigning != other.allowSigning) return false
                if (allowKeyAgreement != other.allowKeyAgreement) return false
                if (curve != other.curve) return false
                if (digests != other.digests) return false

                return true
            }

            override fun hashCode(): Int {
                var result = super.hashCode()
                result = 31 * result + allowSigning.hashCode()
                result = 31 * result + allowKeyAgreement.hashCode()
                result = 31 * result + curve.hashCode()
                result = 31 * result + digests.hashCode()
                return result
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AlgorithmParameters) return false

            if (allowSigning != other.allowSigning) return false
            if (digests != other.digests) return false

            return true
        }

        override fun hashCode(): Int {
            var result = allowSigning.hashCode()
            result = 31 * result + digests.hashCode()
            return result
        }
    }

    @Serializable
    data class KeyProtection(
        val timeout: Duration? = null,
        val deviceLock: Boolean? = null,
        val biometry: Boolean? = null,
        val allowNewBiometricFactors: Boolean? = null,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is KeyProtection) return false

            if (deviceLock != other.deviceLock) return false
            if (biometry != other.biometry) return false
            if (allowNewBiometricFactors != other.allowNewBiometricFactors) return false
            if (timeout != other.timeout) return false

            return true
        }

        override fun hashCode(): Int {
            var result = deviceLock?.hashCode() ?: 0
            result = 31 * result + (biometry?.hashCode() ?: 0)
            result = 31 * result + (allowNewBiometricFactors?.hashCode() ?: 0)
            result = 31 * result + (timeout?.hashCode() ?: 0)
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyConstraints) return false

        if (algorithmParameters != other.algorithmParameters) return false
        if (keyProtection != other.keyProtection) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithmParameters.hashCode()
        result = 31 * result + (keyProtection?.hashCode() ?: 0)
        return result
    }
}