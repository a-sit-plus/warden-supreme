package at.asitplus.attestation.android

import at.asitplus.attestation.android.AttestationRevocationList.Loader.Configuration
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.modules.plus
import java.security.cert.X509Certificate
import java.util.*

internal const val ROBOTO_DEBUG_VERSION = 2

private val jsonDebug by lazy {
    kotlinx.serialization.json.Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        serializersModule += AttestationRevocationList.json.serializersModule
    }
}

@Serializable
class ConfigWithList(val config: Configuration<*>, val list: AttestationRevocationList)

@Serializable
class AndroidDebugAttestationStatement(
    val version: Int,
    val kind: Type,
    val configuration: AndroidAttestationConfiguration,
    @Serializable(with = DateTimeSerializer::class) val verificationTime: Date,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray,
    val attestationStatement: List<@Serializable(with = CertPemSerializer::class) X509Certificate>,
    val revocationLists: List<ConfigWithList>,
) {

    fun checkerFromConfig(): Roboto =
        when (kind) {
            Type.HARDWARE -> HardwareAttestationVerifier(configuration)
            Type.SOFTWARE -> SoftwareAttestationVerifier(configuration)
            Type.NOUGAT_HYBRID -> NougatHybridAttestationVerifier(configuration)
        }

    @JvmName("replaySuspending")
    suspend fun replay() = checkerFromConfig().verifyAttestation(attestationStatement, verificationTime, challenge)

    @JvmName("replay")
    fun replayBlocking() = runBlocking { replay() }


    fun serialize() = jsonDebug.encodeToString(this)

    @Serializable
    enum class Type {
        HARDWARE, SOFTWARE, NOUGAT_HYBRID
    }

    companion object {
        suspend operator fun invoke(
            version: Int,
            verifier: Roboto,
            configuration: AndroidAttestationConfiguration,
            verificationTime: Date,
            challenge: ByteArray,
            attestationStatement: List<X509Certificate>
        ) = AndroidDebugAttestationStatement(
            version,
            when (verifier) {
                is HardwareAttestationVerifier -> Type.HARDWARE
                is SoftwareAttestationVerifier -> Type.SOFTWARE
                is NougatHybridAttestationVerifier -> Type.NOUGAT_HYBRID
                else -> throw IllegalArgumentException("Unknown checker type")
            },
            configuration,
            verificationTime,
            challenge,
            attestationStatement,
            verifier.revocationListFromLastCall()
        )

        fun deserialize(string: String) = jsonDebug.decodeFromString<AndroidDebugAttestationStatement>(string)
    }
}
