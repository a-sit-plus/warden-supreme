@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.ConfigWithList
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.datetime.LocalDate
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

internal val jsonDebug by lazy {
    Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
        serializersModule = AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e }
        classDiscriminator = "type"
    }
}

private val jsonCompact by lazy {
    Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = false
        serializersModule = AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e }
        classDiscriminator = "type"
    }
}


@Serializable
@ExposedCopyVisibility
data class WardenDebugAttestationStatement
internal constructor(
    val method: Method,
    val androidAttestationConfiguration: AndroidAttestationConfiguration?,
    val iosAttestationConfiguration: IosAttestationConfiguration?,
    val genericAttestationProof: List<@Serializable(with = ByteArrayBase64UrlSerializer::class) ByteArray>? = null,
    val keyAttestation: Attestation? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val clientData: ByteArray? = null,
    @Serializable(with = InstantLongSerializer::class) val verificationTime: Instant,
    val verificationTimeOffset: Duration = Duration.ZERO,
    val revocationLists: List<ConfigWithList> = emptyList(),
    override val version: String,
) : DebugStatement<Any> {

    init {
        require(version == wardenVersion) { "Version mismatch! This debug statement was created using Warden Supreme $version. The current version is $wardenVersion" }
    }

    enum class Method {
        LEGACY,
        SUPREME,
        KEY_ATTESTATION_LEGACY,
        KEY_ATTESTATION_LEGACY_RAW,
    }

    /**
     * Creates a new [Makoto] instance based on recorded debug data.
     */
    fun createWarden(): Makoto {
        require(androidAttestationConfiguration != null || iosAttestationConfiguration != null) { "At least one attestation configuration (iOS or Android) must be provided" }

        val androidConfiguration = androidAttestationConfiguration?.let { configuration ->
            if (revocationLists.isEmpty()) configuration
            else configuration.copy(
                revocation = revocationLists.map { AndroidRevocationList.InMemoryLoader.Configuration(it.list) }
            )
        }

        return if (androidConfiguration == null) Makoto(
            iosAttestationConfiguration = iosAttestationConfiguration!!,
            FixedTimeClock(verificationTime),
            verificationTimeOffset
        )
        else if (iosAttestationConfiguration == null) Makoto(
            androidConfiguration,
            FixedTimeClock(verificationTime),
            verificationTimeOffset
        )
        else Makoto(
            androidConfiguration,
            iosAttestationConfiguration,
            FixedTimeClock(verificationTime),
            verificationTimeOffset
        )
    }


    /**
     * Replay the attestation call that was recorded. I.e., it automatically calls the correct `replay` method
     * baaed on how this debug statement was recorded.
     */
    override suspend fun replay() = when (method) {
        Method.LEGACY -> replayGenericAttestation()
        Method.SUPREME -> replayKeyAttestation()
        Method.KEY_ATTESTATION_LEGACY, Method.KEY_ATTESTATION_LEGACY_RAW -> replayKeyAttestationLegacy()
    }

    /**
     * Replays
     * ```kotlin
     *     verifyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         clientData: ByteArray?
     *     ): AttestationResult
     *
     *  ```
     */
    suspend fun replayGenericAttestation() =
        createWarden().verifyAttestation(genericAttestationProof!!, challenge!!, clientData)

    /**
     * Replays
     * ```kotlin
     *     verifyKeyAttestation(
     *         attestationProof: Attestation,
     *         challenge: ByteArray
     *     ): KeyAttestation<PublicKey>
     * ```
     */
    suspend fun replayKeyAttestation() = createWarden().verifyKeyAttestation(keyAttestation!!, challenge!!)

    /**
     * Replays
     * ```kotlin
     *     verifyKeyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         encodedPublicKey: ByteArray
     *     ): KeyAttestation<PublicKey>
     * ```
     */
    suspend fun replayKeyAttestationLegacy() =
        createWarden().verifyKeyAttestation(genericAttestationProof!!, challenge!!, clientData!!)


    override fun serialize() = jsonDebug.encodeToString(this)

    override fun serializeCompact() =
        MultiBase.encode(MultiBase.Base.BASE64_URL, jsonCompact.encodeToString(this).encodeToByteArray())

    override fun toJsonElement(): JsonObject = jsonDebug.encodeToJsonElement(this).jsonObject

    companion object : DebugStatement.Reader<Any, WardenDebugAttestationStatement> {

        override fun deserialize(string: String) = jsonDebug.decodeFromString<WardenDebugAttestationStatement>(string)


        override fun deserializeCompact(string: String) =
            jsonCompact.decodeFromString<WardenDebugAttestationStatement>(MultiBase.decode(string)!!.decodeToString())

        override fun fromJsonElement(jsonElement: JsonElement): WardenDebugAttestationStatement =
            jsonDebug.decodeFromJsonElement(jsonElement)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WardenDebugAttestationStatement) return false

        if (method != other.method) return false
        if (androidAttestationConfiguration != other.androidAttestationConfiguration) return false
        if (iosAttestationConfiguration != other.iosAttestationConfiguration) return false
        if (genericAttestationProof != other.genericAttestationProof) return false
        if (keyAttestation != other.keyAttestation) return false
        if (!challenge.contentEquals(other.challenge)) return false
        if (!clientData.contentEquals(other.clientData)) return false
        if (verificationTime != other.verificationTime) return false
        if (verificationTimeOffset != other.verificationTimeOffset) return false
        if (revocationLists != other.revocationLists) return false
        if (version != other.version) return false

        return true
    }

    override fun hashCode(): Int {
        var result = method.hashCode()
        result = 31 * result + (androidAttestationConfiguration?.hashCode() ?: 0)
        result = 31 * result + (iosAttestationConfiguration?.hashCode() ?: 0)
        result = 31 * result + (genericAttestationProof?.hashCode() ?: 0)
        result = 31 * result + (keyAttestation?.hashCode() ?: 0)
        result = 31 * result + (challenge?.contentHashCode() ?: 0)
        result = 31 * result + (clientData?.contentHashCode() ?: 0)
        result = 31 * result + verificationTime.hashCode()
        result = 31 * result + verificationTimeOffset.hashCode()
        result = 31 * result + revocationLists.hashCode()
        result = 31 * result + (version.hashCode() ?: 0)
        return result
    }
}

class FixedTimeClock(private var epochMilliseconds: Long) : Clock {
    constructor(instant: Instant) : this(instant.toEpochMilliseconds())
    constructor(yyyy: UInt, mm: UInt, dd: UInt) : this(
        LocalDate(yyyy.toInt(), mm.toInt(), dd.toInt()).toEpochDays().days.inWholeMilliseconds
    )

    fun offsetBy(duration: Duration) {
        epochMilliseconds += duration.inWholeMilliseconds
    }

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FixedTimeClock) return false

        if (epochMilliseconds != other.epochMilliseconds) return false

        return true
    }

    override fun hashCode(): Int {
        return epochMilliseconds.hashCode()
    }

    override fun toString(): String {
        return "FixedTimeClock(" +
                "epochMilliseconds=$epochMilliseconds" +
                ")"
    }
}
