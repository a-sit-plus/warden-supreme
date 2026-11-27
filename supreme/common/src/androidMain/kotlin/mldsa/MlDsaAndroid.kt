package at.asitplus.attestation.supreme.mldsa

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.AndroidSignerConfiguration
import at.asitplus.signum.dsl.AndroidSigningKeyConfiguration
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.JcaMappingProvider
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.supreme.os.AndroidKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.AndroidKeystoreSigner
import java.security.PrivateKey

/** First Android API level with ML-DSA in the Android Keystore (Android 17). */
internal const val ANDROID_MLDSA_MIN_SDK = 37

/** An Android Keystore ML-DSA signer. */
class AndroidMlDsaSigner internal constructor(
    jcaPrivateKey: PrivateKey,
    alias: String,
    keyInfo: KeyInfo,
    config: AndroidSignerConfiguration,
    override val publicKey: MlDsaPublicKey,
    attestation: AndroidKeystoreAttestation?,
) : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, "ML-DSA", config, attestation) {
    override val signatureAlgorithm: MlDsaSignatureAlgorithm = publicKey.signatureAlgorithm
    override fun parseSignatureFromJca(jcaSig: ByteArray): Signature = MlDsaSignature(jcaSig)
}

/**
 * Whether the Android Keystore can, in principle, generate ML-DSA keys of this parameter set on this OS version.
 * The device additionally needs KeyMint ≥ 5 (`PackageManager.FEATURE_HARDWARE_KEYSTORE` version ≥ 500);
 * without it, key generation fails in the Keystore.
 */
fun MlDsaParameterSet.isSupportedByAndroidKeystore(): Boolean =
    (this != MlDsaParameterSet.ML_DSA_44) && (Build.VERSION.SDK_INT >= ANDROID_MLDSA_MIN_SDK)

internal object MlDsaAndroidKeyStoreOperations : AndroidKeyStoreOperationsProvider {

    /** StrongBox support for ML-DSA is undocumented; never request it. */
    @SignumInternals
    override fun supportsStrongBox(algorithm: String): Boolean = false

    override fun initKeyGenSpec(alias: String, config: AndroidSigningKeyConfiguration): Pair<String, KeyGenParameterSpec.Builder>? {
        val set = config.mlDsa.v?.parameterSet ?: return null
        if (!set.isSupportedByAndroidKeystore())
            throw UnsupportedCryptoException(
                "${set.jcaName} is not supported by this device's Android Keystore " +
                        "(requires API $ANDROID_MLDSA_MIN_SDK and KeyMint 5; ML-DSA-44 is never supported)"
            )
        // No AlgorithmParameterSpec and no digests are required: the algorithm name selects the parameter set.
        return set.jcaName to KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    }

    override fun getAndroidKeystoreSigner(
        jcaPrivateKey: PrivateKey,
        alias: String,
        keyInfo: KeyInfo,
        config: AndroidSignerConfiguration,
        publicKey: PublicKey,
        attestation: AndroidKeystoreAttestation?,
    ): AndroidKeystoreSigner? {
        if (publicKey !is MlDsaPublicKey) return null
        return AndroidMlDsaSigner(jcaPrivateKey, alias, keyInfo, config, publicKey, attestation)
    }
}

internal actual fun installPlatformMlDsa() {
    ServiceLoader.register<JcaMappingProvider>(MlDsaJcaMapping(defaultProvider = null))
    ServiceLoader.register<AndroidKeyStoreOperationsProvider>(MlDsaAndroidKeyStoreOperations)
}
