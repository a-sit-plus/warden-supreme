package at.asitplus.attestation.supreme

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.internals.giveToCF
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.AutofreeVariable
import at.asitplus.signum.supreme.hazmat.secKeyRef
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import io.ktor.client.*
import io.ktor.client.engine.darwin.*
import io.ktor.client.engine.darwin.certificates.CertificatePinner
import io.ktor.http.Url
import kotlinx.cinterop.*
import kotlinx.coroutines.runBlocking
import platform.CoreFoundation.CFRetain
import platform.Foundation.NSData
import platform.Foundation.NSUserDefaults
import platform.Security.*
import platform.posix.uname
import platform.posix.utsname

@OptIn(ExperimentalForeignApi::class)
actual fun getDeviceName(): String = memScoped {
    val systemInfo = alloc<utsname>()
    if (uname(systemInfo.ptr) != 0) {
        return "iPhone"
    }
    // e.g. "iPhone15,3"
    systemInfo.machine.toKString()
}

data class PinnedCertificate(val domain: String, val fingerprints: List<String>)
class IosAttestationResult(val successful: Boolean, val message: String, val certificateCount: Int)

class IosAttestationClient private constructor(pins: List<PinnedCertificate>?, allowCellularAccess: Boolean) :
    AttestationClient(HttpClient(Darwin) {
        engine {
            configureRequest {
                setAllowsCellularAccess(allowCellularAccess)
            }
            pins?.let { pins ->
                handleChallenge(CertificatePinner.Builder().apply {
                    pins.forEach {
                        add(it.domain, *(it.fingerprints.toTypedArray()))
                    }
                }.build())
            }
        }
    }) {
    constructor() : this(null, true)
    constructor(allowCellularAccess: Boolean) : this(null, allowCellularAccess)
    constructor(allowCellularAccess: Boolean, pins: List<PinnedCertificate>) : this(pins, allowCellularAccess)
    constructor(pins: List<PinnedCertificate>) : this(pins, true)

    @OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
    @Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
    @Throws(Throwable::class)
    fun getAttestedKey(alias: String): SecKeyRef = runBlocking {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val key = PlatformSigningProvider.getSignerForKey(alias).getOrThrow().secKeyRef
                as? AutofreeVariable<SecKeyRef>
            ?: error("Signum did not expose a SecKey for alias '$alias'")
        requireNotNull(key.value).also(::CFRetain)
    }

    @OptIn(ExperimentalForeignApi::class)
    fun getAttestationKeyCertificate(alias: String): SecCertificateRef? {
        val data = getAttestationCertificateChainData(alias).firstOrNull() ?: return null
        return memScoped { SecCertificateCreateWithData(null, giveToCF(data)) }
    }

    @OptIn(ExperimentalForeignApi::class)
    fun getAttestationCertificateChain(alias: String): List<SecCertificateRef> =
        getAttestationCertificateChainData(alias).mapNotNull { data ->
            memScoped { SecCertificateCreateWithData(null, giveToCF(data)) }
        }

    private fun getAttestationCertificateChainData(alias: String): List<NSData> {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val defaults = NSUserDefaults.standardUserDefaults
        return defaults.arrayForKey(certificateKey(alias))?.filterIsInstance<NSData>()
            ?: defaults.dataForKey(certificateKey(alias))?.let(::listOf)
            ?: emptyList()
    }

    @Throws(Throwable::class)
    suspend fun performAttestation(alias: String, challengeEndpoint: String): IosAttestationResult {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val endpoint = Url(challengeEndpoint)
        require(endpoint.host.isNotBlank() && endpoint.protocol.name in setOf("http", "https")) {
            "Challenge endpoint must be an absolute HTTP(S) URL"
        }

        return when (val response = performAttestationFlow(alias, endpoint) { requested ->
            requested.map {
                require(!it.required) { "Verifier requested unsupported required attribute '${it.name}'" }
                null
            }
        }) {
            is AttestationResponse.Success -> {
                // ponytail: certificates are public data; UserDefaults avoids a second Keychain schema.
                NSUserDefaults.standardUserDefaults.setObject(
                    response.certificateChain.map { it.encodeToDer().toNSData() },
                    certificateKey(alias),
                )
                IosAttestationResult(
                    successful = true,
                    message = "Key attested; received ${response.certificateChain.size} certificate(s)",
                    certificateCount = response.certificateChain.size,
                )
            }

            is AttestationResponse.Failure -> IosAttestationResult(
                successful = false,
                message = "${response.kind}: ${response.explanation ?: "Attestation rejected"}",
                certificateCount = 0,
            )
        }
    }

    private fun certificateKey(alias: String) = "at.asitplus.warden.attestation-certificate.$alias"
}
