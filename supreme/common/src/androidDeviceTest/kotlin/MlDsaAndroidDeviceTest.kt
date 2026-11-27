import android.os.Build
import at.asitplus.attestation.supreme.mldsa.MlDsaParameterSet
import at.asitplus.attestation.supreme.mldsa.MlDsaPublicKey
import at.asitplus.attestation.supreme.mldsa.MlDsaSignature
import at.asitplus.attestation.supreme.mldsa.MlDsaSignatureAlgorithm
import at.asitplus.attestation.supreme.mldsa.installWardenMlDsa
import at.asitplus.attestation.supreme.mldsa.isSupportedByAndroidKeystore
import at.asitplus.attestation.supreme.mldsa.mlDsa
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.os.AndroidKeyStoreProvider
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

/**
 * Android Keystore ML-DSA (API 37+, KeyMint ≥ 5). On older devices only the rejection path is checked.
 * Verification uses the platform JCA, which is all an Android client has; the verifier runs on the JVM.
 */
val MlDsaAndroidDeviceTest by matrixSuite {
    Signum.installWardenMlDsa()
    val message = "warden ml-dsa on android".encodeToByteArray()

    test("below API 37, ML-DSA is rejected before touching the Keystore") {
        if (Build.VERSION.SDK_INT >= 37) return@test
        MlDsaParameterSet.ML_DSA_65.isSupportedByAndroidKeystore() shouldBe false
        shouldThrow<UnsupportedCryptoException> {
            AndroidKeyStoreProvider.createSigningKey("warden-mldsa-old") { mlDsa { } }
        }
    }

    data(
        "attested key: create, sign, verify",
        listOf(MlDsaParameterSet.ML_DSA_65, MlDsaParameterSet.ML_DSA_87),
        nameFn = { _, it -> it.jcaName },
    ) test { set ->
        if (!set.isSupportedByAndroidKeystore()) return@test // requires API 37
        val alias = "warden-mldsa-" + Random.nextLong().toULong().toString(16)
        try {
            val signer = AndroidKeyStoreProvider.createSigningKey(alias) {
                mlDsa { parameterSet = set }
                hardware { attestation { challenge = Random.nextBytes(16) } }
            }
            val publicKey = signer.publicKey.shouldBeInstanceOf<MlDsaPublicKey>()
            publicKey.parameterSet shouldBe set
            signer.signatureAlgorithm shouldBe MlDsaSignatureAlgorithm[set]
            // the attested leaf carries the ML-DSA key; the chain above it is EC
            signer.attestation.shouldBeInstanceOf<at.asitplus.signum.indispensable.AndroidKeystoreAttestation>()
                .certificateChain.first().publicKey shouldBe publicKey

            val signature = signer.sign(message).signature.shouldBeInstanceOf<MlDsaSignature>()
            signature.rawBytes.size shouldBe set.signatureSize
            java.security.Signature.getInstance("ML-DSA").run {
                initVerify(publicKey.toJcaPublicKey()); update(message); verify(signature.rawBytes)
            } shouldBe true
        } finally {
            runCatching { AndroidKeyStoreProvider.deleteSigningKey(alias) }
        }
    }
}
