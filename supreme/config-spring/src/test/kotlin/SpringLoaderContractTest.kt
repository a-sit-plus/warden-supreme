package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import org.springframework.boot.context.properties.source.ConfigurationPropertySources
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.StandardEnvironment
import org.springframework.core.env.SystemEnvironmentPropertySource

val SpringLoaderContractTest by testSuite {
    "fromSpringMap matches canonical oracle for minimal and maximal configs" {
        assertSpringMapMatchesCanonical(SpringFixtures.androidMinimal)
        assertSpringMapMatchesCanonical(SpringFixtures.androidMaximal)
        assertSpringMapMatchesCanonical(SpringFixtures.iosMinimal)
        assertSpringMapMatchesCanonical(SpringFixtures.iosMaximal)
        assertSpringMapMatchesCanonical(SpringFixtures.supremeAndroidOnly)
        assertSpringMapMatchesCanonical(SpringFixtures.supremeIosOnly)
        assertSpringMapMatchesCanonical(SpringFixtures.supremeDualPlatform)
    }

    "spring environment binds prefixed subtrees without leaking sibling config" {
        val alpha = environmentOf(
            "alpha.applications[0].packageName" to "at.asitplus.alpha",
            "alpha.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
            "beta.applications[0].packageName" to "at.asitplus.beta",
            "beta.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        )

        val alphaLoaded = AndroidAttestationConfiguration.fromSpringEnvironment(alpha, "alpha")
        val betaLoaded = AndroidAttestationConfiguration.fromSpringEnvironment(alpha, "beta")

        alphaLoaded.applications.single().packageName shouldBe "at.asitplus.alpha"
        betaLoaded.applications.single().packageName shouldBe "at.asitplus.beta"
    }

    "spring binder reconstructs indexed lists from flat properties for all config types" {
        val android = environmentOf(
            "cfg.applications[0].packageName" to "at.asitplus.android",
            "cfg.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
            "cfg.verifiedBootKeys[0]" to "OEM",
            "cfg.verifiedBootKeys[1]" to "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        val ios = environmentOf(
            "cfg.applications[0].teamIdentifier" to "9CYHJNG644",
            "cfg.applications[0].bundleIdentifier" to "at.asitplus.ios",
            "cfg.applications[0].sandbox" to true,
            "cfg.iosVersion.semVer" to "17.4.1",
            "cfg.iosVersion.buildNumber" to "21E236",
        )
        val supreme = environmentOf(
            "cfg.android.applications[0].packageName" to "at.asitplus.supreme",
            "cfg.android.applications[0].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
            "cfg.ios.applications[0].teamIdentifier" to "9CYHJNG644",
            "cfg.ios.applications[0].bundleIdentifier" to "at.asitplus.supreme-ios",
            "cfg.clock" to "system",
        )

        AndroidAttestationConfiguration.fromSpringEnvironment(android, "cfg").applications.single().packageName shouldBe "at.asitplus.android"
        IosAttestationConfiguration.fromSpringEnvironment(ios, "cfg").applications.single().bundleIdentifier shouldBe "at.asitplus.ios"
        SupremeConfiguration.fromSpringEnvironment(supreme, "cfg").android!!.applications.single().packageName shouldBe "at.asitplus.supreme"
    }

    "spring environment variables reject snake case inside property segments for raw map binding" {
        val android = systemEnvironmentOf(
            "ATTESTATION_ANDROID_APPLICATIONS_0_PACKAGE_NAME" to "at.asitplus.android.env",
            "ATTESTATION_ANDROID_APPLICATIONS_0_SIGNER_FINGERPRINTS_0" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
        )

        shouldThrow<IllegalArgumentException> {
            AndroidAttestationConfiguration.fromSpringEnvironment(android, "attestation.android")
        }
    }

    "spring blanks become null only for optional values and fail for required ones" {
        val supreme = SupremeConfiguration.fromSpringMap(
            mapOf(
                "android" to mapOf(
                    "applications" to listOf(
                        mapOf(
                            "packageName" to "at.asitplus.blank",
                            "signerFingerprints" to listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7A")
                        )
                    )
                ),
                "ios" to null,
                "clock" to "system",
                "genericDeviceNameOID" to ""
            )
        )

        supreme.genericDeviceNameOID.shouldBeNull()

        shouldThrow<Throwable> {
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

    "spring rejects missing prefixes non-string nested keys and malformed indexed collections" - {
        "missing prefix" {
            shouldThrow<IllegalArgumentException> {
                AndroidAttestationConfiguration.fromSpringEnvironment(environmentOf(), "missing")
            }
        }

        "non string nested keys" {
            shouldThrow<IllegalArgumentException> {
                mapOf("applications" to mapOf(1 to "boom")).toAttestationJsonObject()
            }
        }

        "non contiguous indexed properties" {
            val nonContiguous = environmentOf(
                "cfg.applications[1].packageName" to "at.asitplus.gap",
                "cfg.applications[1].signerFingerprints[0]" to "NLl2LE1skNSEMZQMV73nMUJYsmQg7A",
            )

            shouldThrow<Throwable> {
                AndroidAttestationConfiguration.fromSpringEnvironment(nonContiguous, "cfg")
            }
        }
    }

    "spring rejects invalid subtype payloads and invalid ios version data" - {
        "invalid revocation subtype" {
            shouldThrow<Throwable> {
                AndroidAttestationConfiguration.fromSpringMap(
                    mapOf(
                        "applications" to listOf(
                            mapOf(
                                "packageName" to "at.asitplus.invalid",
                                "signerFingerprints" to listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7A")
                            )
                        ),
                        "revocation" to listOf(mapOf("type" to "unknown-loader"))
                    )
                )
            }
        }

        "invalid clock subtype" {
            shouldThrow<Throwable> {
                SupremeConfiguration.fromSpringMap(
                    mapOf(
                        "android" to mapOf(
                            "applications" to listOf(
                                mapOf(
                                    "packageName" to "at.asitplus.invalid-clock",
                                    "signerFingerprints" to listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7A")
                                )
                            )
                        ),
                        "ios" to null,
                        "clock" to mapOf("type" to "unknown-clock")
                    )
                )
            }
        }

        "invalid ios version data" {
            shouldThrow<Throwable> {
                IosAttestationConfiguration.fromSpringMap(
                    mapOf(
                        "applications" to listOf(
                            mapOf(
                                "teamIdentifier" to "9CYHJNG644",
                                "bundleIdentifier" to "at.asitplus.invalid-ios"
                            )
                        ),
                        "iosVersion" to mapOf(
                            "semVer" to "not-a-semver",
                            "buildNumber" to "21E236"
                        )
                    )
                )
            }
        }
    }

    "spring map conversion preserves scalar coercion and only turns contiguous numeric maps into arrays" {
        val converted = mapOf(
            "bool" to true,
            "long" to 7L,
            "double" to 3.5,
            "enum" to SampleEnum.VALUE,
            "list" to mapOf("0" to "first", "1" to 2),
            "gappy" to mapOf("0" to "first", "2" to "third")
        ).toAttestationJsonObject()

        converted["bool"] shouldBe JsonPrimitive(true)
        converted["long"] shouldBe JsonPrimitive(7)
        converted["double"] shouldBe JsonPrimitive(3.5)
        converted["enum"] shouldBe JsonPrimitive("VALUE")
        converted["list"] shouldBe JsonArray(listOf(JsonPrimitive("first"), JsonPrimitive(2)))
        converted["gappy"] shouldBe JsonObject(mapOf("0" to JsonPrimitive("first"), "2" to JsonPrimitive("third")))
    }
}

private fun <A : AttestationConfiguration> assertSpringMapMatchesCanonical(expected: A) {
    val springValue = expected.toJsonElement().toSpringValue()
    require(springValue is Map<*, *>) { "Expected top-level map for ${expected::class.qualifiedName}" }
    val springMap = springValue.entries.associate { (key, value) ->
        require(key is String) { "Top-level config map keys must be strings" }
        key to value
    }
    val loaded = when (expected) {
        is AndroidAttestationConfiguration -> AndroidAttestationConfiguration.fromSpringMap(springMap)
        is IosAttestationConfiguration -> IosAttestationConfiguration.fromSpringMap(springMap)
        is SupremeConfiguration -> SupremeConfiguration.fromSpringMap(springMap)
        else -> error("Unsupported configuration type ${expected::class.qualifiedName}")
    }

    loaded shouldBe expected
}

private fun environmentOf(vararg properties: Pair<String, Any?>): ConfigurableEnvironment =
    StandardEnvironment().apply {
        val source = linkedMapOf<String, Any>()
        properties.forEach { (key, value) ->
            if (value != null) source[key] = value
        }
        propertySources.addFirst(MapPropertySource("test", source))
        ConfigurationPropertySources.attach(this)
    }

private fun systemEnvironmentOf(vararg properties: Pair<String, Any?>): ConfigurableEnvironment =
    StandardEnvironment().apply {
        val source = linkedMapOf<String, Any>()
        properties.forEach { (key, value) ->
            if (value != null) source[key] = value
        }
        propertySources.addFirst(SystemEnvironmentPropertySource("test-system-env", source))
        ConfigurationPropertySources.attach(this)
    }

private fun JsonElement.toSpringValue(): Any? = when (this) {
    JsonNull -> null
    is JsonObject -> entries.associate { (key, value) -> key to value.toSpringValue() }
    is JsonArray -> map { it.toSpringValue() }
    is JsonPrimitive -> if (isString) content else booleanOrNull ?: longOrNull ?: doubleOrNull ?: content
}

private enum class SampleEnum {
    VALUE
}

private object SpringFixtures {
    val androidMinimal = AndroidAttestationConfiguration(
        singleApp = AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.android-min",
            signerFingerprints = setOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex())
        )
    )

    val androidMaximal = AndroidAttestationConfiguration(
        applications = listOf(
            AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation-client",
                signerFingerprints = setOf(
                    "34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()
                ),
                appVersion = 42,
                androidVersionOverride = 340000,
                patchLevelOverride = PatchLevel(2025, 3, maxFuturePatchLevelMonths = 2),
                requireRemoteKeyProvisioningOverride = true,
                requireStrongBoxOverride = true,
                verifiedBootKeys = linkedSetOf(
                    VerifiedBootKey.OEM,
                    VerifiedBootKey.Digest(
                        "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
                            .parseHex()
                    )
                )
            )
        ),
        androidVersion = 330000,
        patchLevel = PatchLevel(2025, 2, maxFuturePatchLevelMonths = 3),
        requireStrongBox = true,
        allowBootloaderUnlock = false,
        requireRollbackResistance = true,
        ignoreLeafValidity = false,
        verificationSecondsOffset = 90,
        attestationStatementValiditySeconds = 300,
        disableHardwareAttestation = false,
        enableSoftwareAttestation = true,
        revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://localhost:2345"),
            AndroidRevocationList.FileLoader.Configuration("./localrevocation.json")
        ),
        requireRemoteKeyProvisioning = true,
        verifiedBootKeys = linkedSetOf(
            VerifiedBootKey.OEM,
            VerifiedBootKey.Digest(
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
                    .parseHex()
            )
        ),
        supremeParser = true
    )

    val iosMinimal = IosAttestationConfiguration(
        singleApp = IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.ios-min"
        )
    )

    val iosMaximal = IosAttestationConfiguration(
        applications = listOf(
            IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
                sandbox = true,
                iosVersionOverride = IosAttestationConfiguration.OsVersions("17.5.1", "21F90"),
                trustedRootOverrides = linkedSetOf(APPLE_DEFAULT_TRUSTED_ROOTS.first())
            )
        ),
        iosVersion = IosAttestationConfiguration.OsVersions("17.4.1", "21E236"),
        attestationStatementValiditySeconds = 900,
        trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS
    )

    val supremeAndroidOnly = SupremeConfiguration(androidMinimal)
    val supremeIosOnly = SupremeConfiguration(iosMinimal)
    val supremeDualPlatform = SupremeConfiguration(androidMaximal, iosMaximal)
}
