@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val jsonDebug = kotlinx.serialization.json.Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}


@Serializable
@ExposedCopyVisibility
data class WardenDebugAttestationStatement
internal constructor(
    val method: Method,
    val androidAttestationConfiguration: AndroidAttestationConfiguration,
    val iosAttestationConfiguration: IOSAttestationConfiguration,
    val genericAttestationProof: List<@Serializable(with = ByteArrayBase64UrlSerializer::class) ByteArray>? = null,
    val keyAttestation: Attestation? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray? = null,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val clientData: ByteArray? = null,
    @Serializable(with = InstantLongSerializer::class) val verificationTime: Instant,
    val verificationTimeOffset: Duration = Duration.ZERO
) {

    enum class Method {
        LEGACY,
        SUPREME,
        KEY_ATTESTATION_LEGACY,
        KEY_ATTESTATION_LEGACY_RAW,
    }

    /**
     * Creates a new [Warden] instance based on recorded debug data.
     * @param ignoreProxy enables direct connection to HTTP endpoints. Helpful for replaying attestations in a network setup that differs from the one where a debug statement was recorded.
     */
    fun createWarden(ignoreProxy: Boolean): Warden = Warden(
        if (ignoreProxy) androidAttestationConfiguration.copy(httpProxy = null) else androidAttestationConfiguration,
        iosAttestationConfiguration,
        FixedTimeClock(verificationTime),
        verificationTimeOffset
    )


    /**
     * Replay the attestation call that was recorded. I.e., it automatically calls the correct `replay` method
     * baaed on how this debug statement was recorded.
     * @param ignoreProxy enables direct connection to HTTP endpoints. Helpful for replaying attestations in a network setup that differs from the one where a debug statement was recorded.
     */
    fun replaySmart(ignoreProxy: Boolean) = when (method) {
        Method.LEGACY -> replayGenericAttestation(ignoreProxy)
        Method.SUPREME -> replayKeyAttestation(ignoreProxy)
        Method.KEY_ATTESTATION_LEGACY, Method.KEY_ATTESTATION_LEGACY_RAW -> replayKeyAttestationLegacy(ignoreProxy)
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
     *
     * @param ignoreProxy enables direct connection to HTTP endpoints. Helpful for replaying attestations in a network setup that differs from the one where a debug statement was recorded.
     */
    fun replayGenericAttestation(ignoreProxy: Boolean) =
        createWarden(ignoreProxy).verifyAttestation(genericAttestationProof!!, challenge!!, clientData)

    /**
     * Replays
     * ```kotlin
     *     verifyKeyAttestation(
     *         attestationProof: Attestation,
     *         challenge: ByteArray
     *     ): KeyAttestation<PublicKey>
     * ```
     * @param ignoreProxy enables direct connection to HTTP endpoints. Helpful for replaying attestations in a network setup that differs from the one where a debug statement was recorded.
     */
    fun replayKeyAttestation(ignoreProxy: Boolean) =
        createWarden(ignoreProxy).verifyKeyAttestation(keyAttestation!!, challenge!!)

    /**
     * Replays
     * ```kotlin
     *     verifyKeyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         encodedPublicKey: ByteArray
     *     ): KeyAttestation<PublicKey>
     * ```
     *
     * @param ignoreProxy enables direct connection to HTTP endpoints. Helpful for replaying attestations in a network setup that differs from the one where a debug statement was recorded.
     */
    fun replayKeyAttestationLegacy(ignoreProxy: Boolean) =
        createWarden(ignoreProxy).verifyKeyAttestation(genericAttestationProof!!, challenge!!, clientData!!)

    /**
     * Produces a JSON representation of this debug info
     */
    fun serialize() = jsonDebug.encodeToString(this)

    /**
     * serializes and multibase-encodes this debug info
     */
    fun serializeCompact() = MultiBase.encode(MultiBase.Base.BASE64_URL, serialize().encodeToByteArray())

    companion object {
        /**
         * Parses a debug info from JSON
         */
        fun deserialize(string: String) = jsonDebug.decodeFromString<WardenDebugAttestationStatement>(string)

        /**
         * Multibase-decodes and deserializes a debug info string.
         */
        fun deserializeCompact(string: String) = deserialize(MultiBase.decode(string)!!.decodeToString())
    }
}

class FixedTimeClock(private val epochMilliseconds: Long) : Clock {
    constructor(instant: Instant) : this(instant.toEpochMilliseconds())
    constructor(yyyy: UInt, mm: UInt, dd: UInt) : this(
        Instant.parse(
            "$yyyy-${
                mm.toString().let { if (it.length < 2) "0$it" else it }
            }-${
                dd.toString().let { if (it.length < 2) "0$it" else it }
            }T00:00:00.000Z"
        )
    )

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)
}