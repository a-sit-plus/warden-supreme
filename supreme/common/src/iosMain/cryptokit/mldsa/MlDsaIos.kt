@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package at.asitplus.attestation.supreme.mldsa

import at.asitplus.attestation.supreme.mldsa.internal.ios.WardenMlDsa
import at.asitplus.attestation.supreme.mldsa.internal.ios.WardenMlDsaErrorCodeUnlockFailed
import at.asitplus.attestation.supreme.mldsa.internal.ios.WardenMlDsaErrorCodeUnsupported
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.DISCOURAGED
import at.asitplus.signum.dsl.IosSignerConfiguration
import at.asitplus.signum.dsl.IosSignerSigningConfiguration
import at.asitplus.signum.dsl.IosSigningKeyConfiguration
import at.asitplus.signum.dsl.PREFERRED
import at.asitplus.signum.dsl.REQUIRED
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.UnlockFailed
import at.asitplus.signum.supreme.os.IosKeyMetadata
import at.asitplus.signum.supreme.os.IosKeychainOperationsProvider
import at.asitplus.signum.supreme.os.IosOpaqueKey
import at.asitplus.signum.supreme.os.IosSigner
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.create
import platform.LocalAuthentication.LAContext
import platform.Security.SecAccessControlRef
import platform.posix.memcpy

private fun ByteArray.toNSData(): NSData = usePinned {
    NSData.create(bytes = if (isEmpty()) null else it.addressOf(0), length = size.toULong())
}

private fun NSData.toByteArray(): ByteArray = ByteArray(length.toInt()).also { out ->
    if (out.isNotEmpty()) out.usePinned { memcpy(it.addressOf(0), bytes, length) }
}

/** CryptoKit has ML-DSA-65 and ML-DSA-87 only. */
private val MlDsaParameterSet.cryptoKitId: Long
    get() = when (this) {
        MlDsaParameterSet.ML_DSA_65 -> 65L
        MlDsaParameterSet.ML_DSA_87 -> 87L
        MlDsaParameterSet.ML_DSA_44 -> throw UnsupportedCryptoException("CryptoKit does not support ML-DSA-44")
    }

/** Whether CryptoKit on this device supports [this] parameter set, optionally inside the Secure Enclave. */
fun MlDsaParameterSet.isSupportedByCryptoKit(secureEnclave: Boolean): Boolean =
    (this != MlDsaParameterSet.ML_DSA_44) && WardenMlDsa.isSupported(cryptoKitId, secureEnclave)

private fun NSError.toKotlinException(operation: String): Throwable = when (code) {
    WardenMlDsaErrorCodeUnlockFailed -> UnlockFailed(localizedDescription)
    WardenMlDsaErrorCodeUnsupported -> UnsupportedCryptoException("$operation: $localizedDescription")
    else -> IllegalStateException("$operation: $localizedDescription")
}

private inline fun <T : Any> callShim(operation: String, block: (kotlinx.cinterop.CPointer<ObjCObjectVar<NSError?>>) -> T?): T =
    memScoped {
        val error = alloc<ObjCObjectVar<NSError?>>()
        block(error.ptr) ?: throw (error.value?.toKotlinException(operation)
            ?: IllegalStateException("$operation failed without an error"))
    }

/** Persisted with the key (Supreme's opaque-key metadata), so signers can be restored. */
@Serializable
private data class MlDsaIosKeyMetadata(val warden: String = KIND, val parameterSet: MlDsaParameterSet, val secureEnclave: Boolean) {
    companion object {
        const val KIND = "ml-dsa"
        fun from(element: JsonElement?): MlDsaIosKeyMetadata? = element?.let {
            runCatching { Json.decodeFromJsonElement<MlDsaIosKeyMetadata>(it) }.getOrNull()?.takeIf { it.warden == KIND }
        }
    }
}

/** A CryptoKit ML-DSA signer (Secure Enclave, or software when hardware backing is discouraged). */
@OptIn(SignumInternals::class)
class IosMlDsaSigner internal constructor(
    alias: String,
    override val publicKey: MlDsaPublicKey,
    metadata: IosKeyMetadata,
    config: IosSignerConfiguration,
    /** Whether the key lives in the Secure Enclave. */
    val isSecureEnclaveKey: Boolean,
) : IosSigner(alias, metadata, config) {
    override val signatureAlgorithm: MlDsaSignatureAlgorithm = publicKey.signatureAlgorithm

    @SignumInternals
    override val secKeyType = null

    override fun bytesToSignature(sigBytes: ByteArray): Signature = MlDsaSignature(sigBytes)

    private suspend fun signWithShim(message: ByteArray, signingConfig: IosSignerSigningConfiguration): ByteArray {
        val blob = loadOpaqueKeyBlob()
        return withUnlockContext(signingConfig) { context: LAContext? ->
            // The shim's header only forward-declares LAContext; both names denote the same Objective-C class.
            @Suppress("CAST_NEVER_SUCCEEDS")
            val shimContext = context as objcnames.classes.LAContext?
            val result = callShim("ML-DSA signing") { error ->
                WardenMlDsa.sign(
                    publicKey.parameterSet.cryptoKitId,
                    keyBlob = blob.toNSData(),
                    secureEnclave = isSecureEnclaveKey,
                    context = shimContext,
                    message = message.toNSData(),
                    error = error,
                )
            }
            check(result.publicKey.toByteArray().contentEquals(publicKey.rawBytes)) {
                "The stored ML-DSA key for alias $alias does not match its public key"
            }
            result.signature.toByteArray()
        }
    }

    @SignumInternals
    override suspend fun signNative(data: SignatureInput, signingConfig: IosSignerSigningConfiguration): ByteArray {
        val message = data.data.fold(ByteArray(0)) { acc, chunk -> acc + chunk }
        return signWithShim(message, signingConfig)
    }

    override suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<IosSignerSigningConfiguration>) {
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            // Signing (which runs inside withUnlockContext) records the authentication for reuse.
            val _ = sign(SignatureInput(byteArrayOf()), configure)
        }
    }
}

internal object MlDsaIosOperations : IosKeychainOperationsProvider {
    override fun getOperationsBundle(config: IosSigningKeyConfiguration): IosKeychainOperationsProvider.OperationsBundle? = null

    @SignumInternals
    override fun generateOpaqueKey(alias: String, config: IosSigningKeyConfiguration, accessControl: SecAccessControlRef): IosOpaqueKey? {
        val set = config.mlDsa.v?.parameterSet ?: return null
        val hardware = config.hardware.v
        val protectionRequested = hardware.protection.v != null
        val useSecureEnclave = when (hardware.backing) {
            REQUIRED -> true
            PREFERRED -> set.isSupportedByCryptoKit(secureEnclave = true)
            DISCOURAGED -> false
        }
        if (!set.isSupportedByCryptoKit(useSecureEnclave))
            throw UnsupportedCryptoException(
                "${set.jcaName} is not supported by CryptoKit on this device " +
                        "(requires iOS 26${if (useSecureEnclave) " and a Secure Enclave" else ""}; ML-DSA-44 is never supported)"
            )
        // Software keys are stored as a plain Keychain blob; Supreme only enforces access control inside the Secure Enclave.
        if (!useSecureEnclave && protectionRequested)
            throw UnsupportedCryptoException("Protected ML-DSA keys require the Secure Enclave")

        val key = callShim("ML-DSA key generation") { error ->
            WardenMlDsa.generate(
                set.cryptoKitId,
                accessControl = if (useSecureEnclave) accessControl else null,
                secureEnclave = useSecureEnclave,
                error = error,
            )
        }
        return IosOpaqueKey(
            publicKey = MlDsaPublicKey(set, key.publicKey.toByteArray()),
            keyBlob = key.keyBlob.toByteArray(),
            usedSecureEnclave = key.secureEnclave,
            algSpecific = Json.encodeToJsonElement(MlDsaIosKeyMetadata(parameterSet = set, secureEnclave = key.secureEnclave)),
        )
    }

    override fun makeIosSigner(alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner? {
        if (publicKey !is MlDsaPublicKey) return null
        val stored = MlDsaIosKeyMetadata.from(metadata.algSpecific) ?: return null
        require(stored.parameterSet == publicKey.parameterSet) { "Stored ML-DSA metadata does not match the key of $alias" }
        return IosMlDsaSigner(alias, publicKey, metadata, config, stored.secureEnclave)
    }
}

internal actual fun installPlatformMlDsa() {
    ServiceLoader.register<IosKeychainOperationsProvider>(MlDsaIosOperations)
}
