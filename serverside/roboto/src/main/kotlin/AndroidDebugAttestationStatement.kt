package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
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
        checker: AndroidAttestationChecker,
        configuration: AndroidAttestationConfiguration,
        verificationTime: Date,
        challenge: ByteArray,
        attestationStatement: List<X509Certificate>
    ) : this(
        when (checker) {
            is HardwareAttestationChecker -> Type.HARDWARE
            is SoftwareAttestationChecker -> Type.SOFTWARE
            is NougatHybridAttestationChecker -> Type.NOUGAT_HYBRID
            else -> throw IllegalArgumentException("Unknown checker type")
        },
        configuration,
        verificationTime,
        challenge,
        attestationStatement

    )

    fun checkerFromConfig(): AndroidAttestationChecker =
        when (kind) {
            Type.HARDWARE -> HardwareAttestationChecker(configuration)
            Type.SOFTWARE -> SoftwareAttestationChecker(configuration)
            Type.NOUGAT_HYBRID -> NougatHybridAttestationChecker(configuration)
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
