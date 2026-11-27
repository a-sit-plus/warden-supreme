@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

import at.asitplus.attestation.supreme.mldsa.MlDsaParameterSet
import at.asitplus.attestation.supreme.mldsa.MlDsaPublicKey
import at.asitplus.attestation.supreme.mldsa.MlDsaSignature
import at.asitplus.attestation.supreme.mldsa.MlDsaSignatureAlgorithm
import at.asitplus.attestation.supreme.mldsa.installWardenMlDsa
import at.asitplus.attestation.supreme.mldsa.internal.ios.WardenMlDsa
import at.asitplus.attestation.supreme.mldsa.isSupportedByCryptoKit
import at.asitplus.attestation.supreme.mldsa.mlDsa
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.DISCOURAGED
import at.asitplus.signum.dsl.PREFERRED
import at.asitplus.signum.dsl.REQUIRED
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.supreme.os.IosKeychainProvider
import at.asitplus.signum.supreme.os.IosSigner
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import kotlin.random.Random

private fun ByteArray.nsData(): NSData = usePinned { NSData.create(bytes = it.addressOf(0), length = size.toULong()) }

private suspend fun withAlias(block: suspend (String) -> Unit) {
    val alias = "warden-mldsa-" + Random.nextLong().toULong().toString(16)
    try { block(alias) } finally { runCatching { IosKeychainProvider.deleteSigningKey(alias) } }
}

private val iosSets = listOf(MlDsaParameterSet.ML_DSA_65, MlDsaParameterSet.ML_DSA_87)

val MlDsaIosTest by matrixSuite {
    Signum.installWardenMlDsa()
    val message = "warden ml-dsa on ios".encodeToByteArray()

    test("CryptoKit availability on the simulator") {
        MlDsaParameterSet.ML_DSA_44.isSupportedByCryptoKit(secureEnclave = false) shouldBe false
        iosSets.forEach { it.isSupportedByCryptoKit(secureEnclave = false) shouldBe true }
    }

    data("software key: create, sign, reload, delete", iosSets, nameFn = { _, it -> it.jcaName }) test { set ->
        withAlias { alias ->
            val signer = IosKeychainProvider.createSigningKey(alias) {
                mlDsa { parameterSet = set }
                hardware { backing = DISCOURAGED }
            }
            val publicKey = signer.publicKey.shouldBeInstanceOf<MlDsaPublicKey>()
            publicKey.parameterSet shouldBe set
            signer.signatureAlgorithm shouldBe MlDsaSignatureAlgorithm[set]
            // SPKI round trip
            PublicKey.fromAsn1(publicKey.asn1.toDer()) shouldBe publicKey

            val signature = signer.sign(message).signature.shouldBeInstanceOf<MlDsaSignature>()
            signature.rawBytes.size shouldBe set.signatureSize
            WardenMlDsa.verify(set.jcaName.takeLast(2).toLong(), publicKey.rawBytes.nsData(), message.nsData(), signature.rawBytes.nsData()) shouldBe true
            WardenMlDsa.verify(set.jcaName.takeLast(2).toLong(), publicKey.rawBytes.nsData(), "other".encodeToByteArray().nsData(), signature.rawBytes.nsData()) shouldBe false

            val reloaded = IosKeychainProvider.getSignerForKey(alias).shouldBeInstanceOf<IosSigner>()
            reloaded.publicKey shouldBe publicKey
            val second = reloaded.sign(message).signature.shouldBeInstanceOf<MlDsaSignature>()
            WardenMlDsa.verify(set.jcaName.takeLast(2).toLong(), publicKey.rawBytes.nsData(), message.nsData(), second.rawBytes.nsData()) shouldBe true

            IosKeychainProvider.deleteSigningKey(alias)
            shouldThrow<Throwable> { IosKeychainProvider.getSignerForKey(alias) }
        }
    }

    test("PREFERRED falls back to a software key without a Secure Enclave") {
        withAlias { alias ->
            val signer = IosKeychainProvider.createSigningKey(alias) {
                mlDsa { }
                hardware { backing = PREFERRED }
            }
            signer.publicKey.shouldBeInstanceOf<MlDsaPublicKey>().parameterSet shouldBe MlDsaParameterSet.ML_DSA_65
            signer.sign(message).signature.shouldBeInstanceOf<MlDsaSignature>()
        }
    }

    test("REQUIRED needs a Secure Enclave") {
        if (MlDsaParameterSet.ML_DSA_65.isSupportedByCryptoKit(secureEnclave = true)) return@test // real device
        withAlias { alias ->
            shouldThrow<UnsupportedCryptoException> {
                IosKeychainProvider.createSigningKey(alias) { mlDsa { }; hardware { backing = REQUIRED } }
            }
        }
    }

    test("protected software keys are rejected") {
        withAlias { alias ->
            shouldThrow<UnsupportedCryptoException> {
                IosKeychainProvider.createSigningKey(alias) {
                    mlDsa { }
                    hardware { backing = DISCOURAGED; protection { } }
                }
            }
        }
    }

    test("ML-DSA-44 is rejected") {
        withAlias { alias ->
            shouldThrow<UnsupportedCryptoException> {
                IosKeychainProvider.createSigningKey(alias) {
                    mlDsa { parameterSet = MlDsaParameterSet.ML_DSA_44 }
                    hardware { backing = DISCOURAGED }
                }
            }
        }
    }
}
