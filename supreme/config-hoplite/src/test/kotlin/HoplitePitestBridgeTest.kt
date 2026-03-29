package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.SupremeConfiguration
import com.sksamuel.hoplite.ArrayNode
import com.sksamuel.hoplite.BooleanNode
import com.sksamuel.hoplite.ConfigException
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.DoubleNode
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.LongNode
import com.sksamuel.hoplite.MapNode
import com.sksamuel.hoplite.Node
import com.sksamuel.hoplite.NullNode
import com.sksamuel.hoplite.Pos
import com.sksamuel.hoplite.StringNode
import com.sksamuel.hoplite.Undefined
import com.sksamuel.hoplite.addFileSource
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.reflect.typeOf

class HoplitePitestBridgeTest {
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun reifiedDecoderSupportsOnlyItsTargetType() {
        val decoder = AndroidAttestationConfiguration.hopliteDecoder()

        assertTrue(decoder.supports(typeOf<AndroidAttestationConfiguration>()))
        assertFalse(decoder.supports(typeOf<IosAttestationConfiguration>()))
    }

    @Test
    fun explicitDecoderLoadsYamlAndJsonLikeCanonicalReaders() {
        val expected = HoplitePitestFixtures.androidMinimal

        val fromYaml = loadWithHoplite(expected.toYamlString(), ".yaml", AndroidAttestationConfiguration::class)
        val fromJson = loadWithHoplite(expected.toJsonString(), ".json", AndroidAttestationConfiguration::class)

        assertEquals(expected, fromYaml)
        assertEquals(expected, fromJson)
    }

    @Test
    fun hopliteLoadsExplicitNullForOptionalSupremeOid() {
        val yaml = HoplitePitestFixtures.supremeDualPlatform.toYamlString()
            .replace(
                "genericDeviceNameOID: ${HoplitePitestFixtures.supremeDualPlatform.genericDeviceNameOID}",
                "genericDeviceNameOID: null"
            )

        val loaded = loadWithHoplite(yaml, ".yaml", SupremeConfiguration::class)

        assertNull(loaded.genericDeviceNameOID)
        assertEquals(HoplitePitestFixtures.supremeDualPlatform.android, loaded.android)
        assertEquals(HoplitePitestFixtures.supremeDualPlatform.ios, loaded.ios)
    }

    @Test
    fun hopliteRejectsMalformedPayloads() {
        assertThrows(ConfigException::class.java) {
            loadWithHoplite<AndroidAttestationConfiguration>(
                """
                applications:
                  - packageName: at.asitplus.missing
                """.trimIndent(),
                ".yaml",
                AndroidAttestationConfiguration::class
            )
        }

        val invalidClock = HoplitePitestFixtures.supremeDualPlatform.toYamlString()
            .replace("clock: system", "clock:\n  type: definitely-not-a-clock")

        assertThrows(ConfigException::class.java) {
            loadWithHoplite(invalidClock, ".yaml", SupremeConfiguration::class)
        }
    }

    @Test
    fun hopliteNodeConversionHandlesEverySupportedNodeType() {
        val converted = invokeHopliteNodeToJsonElement(
            MapNode(
                mapOf(
                    "string" to StringNode("text", Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                    "long" to LongNode(7, Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                    "double" to DoubleNode(3.5, Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                    "boolean" to BooleanNode(true, Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                    "null" to NullNode(Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                    "undefined" to Undefined,
                    "array" to ArrayNode(
                        listOf(
                            StringNode("first", Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                            LongNode(2, Pos.NoPos, com.sksamuel.hoplite.decoder.DotPath.root),
                        ),
                        Pos.NoPos,
                        com.sksamuel.hoplite.decoder.DotPath.root
                    )
                ),
                Pos.NoPos,
                com.sksamuel.hoplite.decoder.DotPath.root
            )
        ) as JsonObject

        assertEquals(JsonPrimitive("text"), converted["string"])
        assertEquals(JsonPrimitive(7), converted["long"])
        assertEquals(JsonPrimitive(3.5), converted["double"])
        assertEquals(JsonPrimitive(true), converted["boolean"])
        assertEquals(JsonNull, converted["null"])
        assertEquals(JsonNull, converted["undefined"])
        assertEquals(JsonArray(listOf(JsonPrimitive("first"), JsonPrimitive(2))), converted["array"])
    }
}

private object HoplitePitestFixtures {
    val androidMinimal = AndroidAttestationConfiguration(
        singleApp = AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.android-min",
            signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex())
        )
    )

    val iosMinimal = IosAttestationConfiguration(
        singleApp = IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.ios-min"
        )
    )

    val supremeDualPlatform = SupremeConfiguration(androidMinimal, iosMinimal)
}

@OptIn(ExperimentalHoplite::class)
private fun <A : AttestationConfiguration> loadWithHoplite(
    contents: String,
    suffix: String,
    targetClass: kotlin.reflect.KClass<A>
): A {
    val file = File.createTempFile("warden-pitest-", suffix)
    return try {
        file.writeText(contents)
        ConfigLoaderBuilder.default()
            .withExplicitSealedTypes()
            .addFileSource(file)
            .let { builder ->
                when (targetClass) {
                    AndroidAttestationConfiguration::class -> builder
                        .addDecoder(AndroidAttestationConfiguration.hopliteDecoder())
                        .build()
                        .loadConfigOrThrow<AndroidAttestationConfiguration>()
                    IosAttestationConfiguration::class -> builder
                        .addDecoder(IosAttestationConfiguration.hopliteDecoder())
                        .build()
                        .loadConfigOrThrow<IosAttestationConfiguration>()
                    SupremeConfiguration::class -> builder
                        .addDecoder(SupremeConfiguration.hopliteDecoder())
                        .build()
                        .loadConfigOrThrow<SupremeConfiguration>()
                    else -> error("Unsupported configuration type ${targetClass.qualifiedName}")
                }
            } as A
    } finally {
        file.delete()
    }
}

private fun invokeHopliteNodeToJsonElement(node: Node) =
    Class.forName("at.asitplus.attestation.HopliteKt")
        .getDeclaredMethod("hopliteNodeToJsonElement", Node::class.java)
        .apply { isAccessible = true }
        .invoke(null, node) as kotlinx.serialization.json.JsonElement
