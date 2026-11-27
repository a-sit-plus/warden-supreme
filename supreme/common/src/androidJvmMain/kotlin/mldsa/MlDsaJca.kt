package at.asitplus.attestation.supreme.mldsa

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.JcaMappingProvider
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Provider
import java.security.spec.X509EncodedKeySpec
import java.security.PublicKey as JcaPublicKey
import java.security.Signature as JcaSignature

/**
 * Maps ML-DSA keys, algorithms and signatures to and from the JCA.
 *
 * @param defaultProvider the JCA provider to use when the caller does not specify one
 * (BouncyCastle on the JVM; `null`, i.e. the platform's providers, on Android).
 * @param normalizeSpki canonicalizes a JCA key's X.509 encoding before decoding it. JDK 17's generic
 * `X509Key` re-encodes unknown-algorithm keys with NULL parameters, which RFC 9881 forbids.
 */
internal class MlDsaJcaMapping(
    private val defaultProvider: Provider?,
    private val normalizeSpki: (ByteArray) -> ByteArray = { it },
) : JcaMappingProvider {

    override fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef): JcaSignature? {
        if (algorithm !is MlDsaSignatureAlgorithm) return null
        val name = algorithm.parameterSet.jcaName
        return try {
            when (jcaProviderRef) {
                is JCAProviderRef.ByName -> JcaSignature.getInstance(name, jcaProviderRef.provider)
                is JCAProviderRefO -> JcaSignature.getInstance(name, jcaProviderRef.provider)
                else -> defaultProvider?.let { JcaSignature.getInstance(name, it) } ?: JcaSignature.getInstance(name)
            }
        } catch (e: GeneralSecurityException) {
            throw UnsupportedCryptoException("$name is not supported by the JCA provider ($jcaProviderRef)", e)
        }
    }

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? =
        if (algorithm is MlDsaSignatureAlgorithm) MlDsaSignature(sigBytes) else null

    override fun getJCASignatureBytes(signature: Signature): ByteArray? = (signature as? MlDsaSignature)?.rawBytes

    override fun jcaPublicKeyToPublicKey(publicKey: JcaPublicKey): PublicKey? {
        if (publicKey.format?.equals("X.509", ignoreCase = true) != true) return null
        val encoded = publicKey.encoded ?: return null
        return runCatching { PublicKey.fromAsn1(normalizeSpki(encoded)) }.getOrNull() as? MlDsaPublicKey
    }

    override fun publicKeyToJcaPublicKey(publicKey: PublicKey): JcaPublicKey? {
        if (publicKey !is MlDsaPublicKey) return null
        val spec = X509EncodedKeySpec(publicKey.asn1.toDer())
        return try {
            (defaultProvider?.let { KeyFactory.getInstance("ML-DSA", it) } ?: KeyFactory.getInstance("ML-DSA"))
                .generatePublic(spec)
        } catch (e: GeneralSecurityException) {
            throw UnsupportedCryptoException("No JCA KeyFactory for ${publicKey.parameterSet.jcaName}", e)
        }
    }
}
