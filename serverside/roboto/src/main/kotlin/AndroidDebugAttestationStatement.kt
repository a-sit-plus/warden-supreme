package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.Serializable
import java.security.cert.X509Certificate
import java.util.*

private val jsonDebug = kotlinx.serialization.json.Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}

@Serializable
class AndroidDebugAttestationStatement(
    val kind: Type,
    val configuration: AndroidAttestationConfiguration,
    @Serializable(with = DateTimeSerializer::class) val verificationTime: Date,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray,
    val attestationStatement: List<@Serializable(with = CertPemSerializer::class) X509Certificate>
) {

    constructor(
        verifier: Roboto,
        configuration: AndroidAttestationConfiguration,
        verificationTime: Date,
        challenge: ByteArray,
        attestationStatement: List<X509Certificate>
    ) : this(
        when (verifier) {
            is HardwareAttestationVerifier -> Type.HARDWARE
            is SoftwareAttestationVerifier -> Type.SOFTWARE
            is NougatHybridAttestationVerifier -> Type.NOUGAT_HYBRID
            else -> throw IllegalArgumentException("Unknown checker type")
        },
        configuration,
        verificationTime,
        challenge,
        attestationStatement

    )

    fun checkerFromConfig(): Roboto =
        when (kind) {
            Type.HARDWARE -> HardwareAttestationVerifier(configuration)
            Type.SOFTWARE -> SoftwareAttestationVerifier(configuration)
            Type.NOUGAT_HYBRID -> NougatHybridAttestationVerifier(configuration)
        }

    fun replay() = checkerFromConfig().verifyAttestation(attestationStatement, verificationTime, challenge)


    fun serialize() = jsonDebug.encodeToString(this)

    @Serializable
    enum class Type {
        HARDWARE, SOFTWARE, NOUGAT_HYBRID
    }

    companion object {
        fun deserialize(string: String) = jsonDebug.decodeFromString<AndroidDebugAttestationStatement>(string)
    }
}
