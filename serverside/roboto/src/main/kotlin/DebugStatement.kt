package at.asitplus.attestation

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

interface DebugStatement<R> {
    /**
     * Holds the exact release version string of the Warden release used to create this debug statement.
     * Used to ensure compatibility and traceability between different versions.
     */
    val version: String

    /**
     * Serializes and pretty-prints this debug statement
     */
    fun serialize(): String

    /**
     * serializes and multibase-encodes this debug info
     */
    fun serializeCompact(): String

    /**
     * Converts the debug statement into a JSON representation.
     *
     * @return A JsonObject that represents the canonical, serialized form of the debug statement.
     */
    fun toJsonElement(): JsonObject

    /**
     * Replays the debug statement, reconstructing or reprocessing it as per the underlying attestation verifier's logic.
     * This method is typically used to regenerate or analyse the statement for debugging or auditing purposes.
     *
     * @return An instance of type R representing the result of the replay operation.
     */
    suspend fun replay(): R

    interface Reader<R, D : DebugStatement<R>> {
        fun deserialize(string: String): D
        fun deserializeCompact(string: String): D
        fun fromJsonElement(jsonElement: JsonElement): D
    }
}

/**
 * Replays the debug statement, reconstructing or reprocessing it as per the underlying attestation verifier's logic.
 * This method is typically used to regenerate or analyse the statement for debugging or auditing purposes.
 *
 * @return An instance of type R representing the result of the replay operation.
 */
fun <R : Any> DebugStatement<R>.replayBlocking() = runBlocking { replay() }