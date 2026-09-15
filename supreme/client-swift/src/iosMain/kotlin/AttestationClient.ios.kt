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
import platform.CoreFoundation.CFRetain
import platform.Foundation.NSData
import platform.Foundation.NSUserDefaults
import platform.Security.*

/**
 * Certificate pins consumed by the private Kotlin-to-Swift bridge.
 *
 * @property domain verifier domain matched by the pin
 * @property fingerprints fingerprints in Ktor's `sha256/<base64>` format
 */
data class KotlinPinnedCertificate(val domain: String, val fingerprints: List<String>)

/** Result passed from the private Kotlin bridge to the public Swift façade. */
class KotlinIosAttestationResult(
    val successful: Boolean,
    val message: String,
    val certificateCount: Int,
)

/** Retained key pointer transported through SKIE without suspend-return type erasure. */
@OptIn(ExperimentalForeignApi::class)
class KotlinRetainedSecKey(val pointer: SecKeyRef)

/**
 * Private implementation bridge for the native Swift façade.
 *
 * Pointer ownership is deliberately handled by `WardenSupreme.swift`; applications should use
 * the public `IosAttestationClient` from the final `WardenSupreme` framework.
 */
class KotlinAttestationClient private constructor(pins: List<KotlinPinnedCertificate>?, allowCellularAccess: Boolean) {
    private val client = AttestationClient(HttpClient(Darwin) {
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
    })

    constructor() : this(null, true)
    constructor(allowCellularAccess: Boolean) : this(null, allowCellularAccess)
    constructor(allowCellularAccess: Boolean, pins: List<KotlinPinnedCertificate>) : this(pins, allowCellularAccess)
    constructor(pins: List<KotlinPinnedCertificate>) : this(pins, true)

    /** Returns a retained Security-framework key handle. The Swift façade consumes the retain. */
    @OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
    @Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
    @Throws(Throwable::class)
    suspend fun getAttestedKey(alias: String): KotlinRetainedSecKey {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val key = PlatformSigningProvider.getSignerForKey(alias).getOrThrow().secKeyRef
                as? AutofreeVariable<SecKeyRef>
            ?: error("Signum did not expose a SecKey for alias '$alias'")
        return KotlinRetainedSecKey(requireNotNull(key.value).also(::CFRetain))
    }

    /** Returns the number of certificates stored for [alias]. */
    @OptIn(ExperimentalForeignApi::class)
    fun getAttestationCertificateCount(alias: String): Int = getAttestationCertificateChainData(alias).size

    /**
     * Returns a newly created certificate pointer at [index], or `null` when the index is out of range.
     * The Swift façade consumes ownership of a non-null result.
     */
    @OptIn(ExperimentalForeignApi::class)
    fun getAttestationCertificate(alias: String, index: Int): SecCertificateRef? {
        val data = getAttestationCertificateChainData(alias).getOrNull(index) ?: return null
        return memScoped { SecCertificateCreateWithData(null, giveToCF(data)) }
    }

    private fun getAttestationCertificateChainData(alias: String): List<NSData> {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val defaults = NSUserDefaults.standardUserDefaults
        return defaults.arrayForKey(certificateKey(alias))?.filterIsInstance<NSData>()
            ?: defaults.dataForKey(certificateKey(alias))?.let(::listOf)
            ?: emptyList()
    }

    /**
     * Performs the full verifier ceremony and stores the returned leaf-first certificate chain.
     * [challengeEndpoint] must be an absolute HTTP or HTTPS URL.
     */
    @Throws(Throwable::class)
    suspend fun performAttestation(alias: String, challengeEndpoint: String): KotlinIosAttestationResult {
        require(alias.isNotBlank()) { "Key alias must not be blank" }
        val endpoint = Url(challengeEndpoint)
        require(endpoint.host.isNotBlank() && endpoint.protocol.name in setOf("http", "https")) {
            "Challenge endpoint must be an absolute HTTP(S) URL"
        }

        return when (val response = client.performAttestationFlow(alias, endpoint) { requested ->
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
                KotlinIosAttestationResult(
                    successful = true,
                    message = "Key attested; received ${response.certificateChain.size} certificate(s)",
                    certificateCount = response.certificateChain.size,
                )
            }

            is AttestationResponse.Failure -> KotlinIosAttestationResult(
                successful = false,
                message = "${response.kind}: ${response.explanation ?: "Attestation rejected"}",
                certificateCount = 0,
            )
        }
    }

    private fun certificateKey(alias: String) = "at.asitplus.warden.attestation-certificate.$alias"
}
