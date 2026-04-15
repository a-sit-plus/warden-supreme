package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.SupremeConfiguration
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.StandardEnvironment

class SpringPitestBridgeTest {
    @Test
    fun springMapLoadingMatchesCanonicalReaders() {
        assertEquals(SpringPitestFixtures.androidMinimal, AndroidAttestationConfiguration.fromSpringMap(SpringPitestFixtures.androidSpringMap))
        assertEquals(SpringPitestFixtures.iosMinimal, IosAttestationConfiguration.fromSpringMap(SpringPitestFixtures.iosSpringMap))
        assertEquals(SpringPitestFixtures.supremeDualPlatform, SupremeConfiguration.fromSpringMap(SpringPitestFixtures.supremeSpringMap))
    }

    @Test
    fun springClassOverloadsMatchReifiedEntrypoints() {
        val environment = environmentOf(
            "cfg.applications[0].packageName" to "at.asitplus.android-min",
            "cfg.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        )

        assertEquals(
            AndroidAttestationConfiguration.fromSpringMap(SpringPitestFixtures.androidSpringMap),
            AndroidAttestationConfiguration.fromSpringMap(
                SpringPitestFixtures.androidSpringMap,
                AndroidAttestationConfiguration::class.java
            )
        )
        assertEquals(
            AndroidAttestationConfiguration.fromSpringEnvironment(environment, "cfg"),
            AndroidAttestationConfiguration.fromSpringEnvironment(
                environment,
                "cfg",
                AndroidAttestationConfiguration::class.java
            )
        )
    }

    @Test
    fun springEnvironmentBindingUsesOnlyTheRequestedPrefix() {
        val environment = environmentOf(
            "alpha.applications[0].packageName" to "at.asitplus.alpha",
            "alpha.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
            "beta.applications[0].packageName" to "at.asitplus.beta",
            "beta.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        )

        assertEquals("at.asitplus.alpha", AndroidAttestationConfiguration.fromSpringEnvironment(environment, "alpha").applications.single().packageName)
        assertEquals("at.asitplus.beta", AndroidAttestationConfiguration.fromSpringEnvironment(environment, "beta").applications.single().packageName)
        assertThrows(IllegalArgumentException::class.java) {
            AndroidAttestationConfiguration.fromSpringEnvironment(environment, "missing")
        }
    }

    @Test
    fun springJsonConversionCoversScalarCollectionAndFallbackBranches() {
        val converted = linkedMapOf<String, Any?>(
            "bool" to true,
            "number" to 7,
            "double" to 3.5,
            "blank" to "",
            "nullable" to null,
            "json" to JsonPrimitive("already-json"),
            "list" to listOf("first", 2),
            "array" to arrayOf<Any?>("x", 4),
            "enum" to SpringBridgeEnum.VALUE,
            "object" to SpringBridgeWeirdValue("fallback"),
            "contiguous" to mapOf("0" to "first", "1" to 2),
            "gappy" to mapOf("0" to "first", "2" to "third")
        ).toAttestationJsonObject()

        assertEquals(JsonPrimitive(true), converted["bool"])
        assertEquals(JsonPrimitive(7), converted["number"])
        assertEquals(JsonPrimitive(3.5), converted["double"])
        assertEquals(JsonNull, converted["blank"])
        assertEquals(JsonNull, converted["nullable"])
        assertEquals(JsonPrimitive("already-json"), converted["json"])
        assertEquals(JsonArray(listOf(JsonPrimitive("first"), JsonPrimitive(2))), converted["list"])
        assertEquals(JsonArray(listOf(JsonPrimitive("x"), JsonPrimitive(4))), converted["array"])
        assertEquals(JsonPrimitive("VALUE"), converted["enum"])
        assertEquals(JsonPrimitive("weird:fallback"), converted["object"])
        assertEquals(JsonArray(listOf(JsonPrimitive("first"), JsonPrimitive(2))), converted["contiguous"])
        assertEquals(JsonObject(mapOf("0" to JsonPrimitive("first"), "2" to JsonPrimitive("third"))), converted["gappy"])
    }

    @Test
    fun springBlankOptionalValuesBecomeNullButRequiredOnesStillFail() {
        val loaded = SupremeConfiguration.fromSpringMap(
            mapOf(
                "android" to SpringPitestFixtures.androidSpringMap,
                "ios" to null,
                "clock" to "system",
                "genericDeviceNameOID" to ""
            )
        )

        assertNull(loaded.genericDeviceNameOID)

        assertThrows(Throwable::class.java) {
            IosAttestationConfiguration.fromSpringMap(
                mapOf(
                    "applications" to listOf(
                        mapOf(
                            "teamIdentifier" to "",
                            "bundleIdentifier" to "at.asitplus.invalid"
                        )
                    )
                )
            )
        }
    }

    @Test
    fun springRejectsMalformedCollectionsNestedKeysAndSubtypePayloads() {
        assertThrows(IllegalArgumentException::class.java) {
            mapOf("applications" to mapOf(1 to "boom")).toAttestationJsonObject()
        }

        val nonContiguous = environmentOf(
            "cfg.applications[1].packageName" to "at.asitplus.gap",
            "cfg.applications[1].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        )
        assertThrows(Throwable::class.java) {
            AndroidAttestationConfiguration.fromSpringEnvironment(nonContiguous, "cfg")
        }

        assertThrows(Throwable::class.java) {
            SupremeConfiguration.fromSpringMap(
                mapOf(
                    "android" to SpringPitestFixtures.androidSpringMap,
                    "ios" to null,
                    "clock" to mapOf("type" to "unknown-clock")
                )
            )
        }
    }
}

private object SpringPitestFixtures {
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

    val androidSpringMap = mapOf(
        "applications" to listOf(
            mapOf(
                "packageName" to "at.asitplus.android-min",
                "signerFingerprints" to listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7A")
            )
        )
    )

    val iosSpringMap = mapOf(
        "applications" to listOf(
            mapOf(
                "teamIdentifier" to "9CYHJNG644",
                "bundleIdentifier" to "at.asitplus.ios-min"
            )
        )
    )

    val supremeSpringMap = mapOf(
        "android" to androidSpringMap,
        "ios" to iosSpringMap,
        "clock" to "system"
    )
}

private fun environmentOf(vararg properties: Pair<String, Any?>): ConfigurableEnvironment =
    StandardEnvironment().apply {
        val source = linkedMapOf<String, Any>()
        properties.forEach { (key, value) ->
            if (value != null) source[key] = value
        }
        propertySources.addFirst(MapPropertySource("test", source))
    }

private enum class SpringBridgeEnum {
    VALUE
}

private data class SpringBridgeWeirdValue(
    val value: String
) {
    override fun toString(): String = "weird:$value"
}
