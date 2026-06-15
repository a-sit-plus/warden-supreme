package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.signum.indispensable.encodeToPem
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toKmpCertificate
import com.sksamuel.hoplite.ConfigException
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addFileSource
import com.sksamuel.hoplite.decoder.Decoder
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldBeNull
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.File

@OptIn(ExperimentalHoplite::class)
val HopliteLoaderContractTest by matrixSuite {
    "android loads through hoplite json and yaml exactly like canonical loaders" {
        assertHopliteMatchesCanonical(HopliteFixtures.androidMinimal)
        assertHopliteMatchesCanonical(HopliteFixtures.androidMaximal)
    }

    "ios loads through hoplite json and yaml exactly like canonical loaders" {
        assertHopliteMatchesCanonical(HopliteFixtures.iosMinimal)
        assertHopliteMatchesCanonical(HopliteFixtures.iosMaximal)
    }

    "supreme loads through hoplite json and yaml for android-only ios-only and dual-platform configs" {
        assertHopliteMatchesCanonical(HopliteFixtures.supremeAndroidOnly)
        assertHopliteMatchesCanonical(HopliteFixtures.supremeIosOnly)
        assertHopliteMatchesCanonical(HopliteFixtures.supremeDualPlatform)
    }

    "hoplite accepts explicit null for optional supreme oid" {
        val yaml = HopliteFixtures.supremeDualPlatform.toYamlString()
            .replace(
                "genericDeviceNameOID: ${HopliteFixtures.supremeDualPlatform.genericDeviceNameOID}",
                "genericDeviceNameOID: null"
            )

        val loaded = loadYaml<SupremeConfiguration>(yaml)
        loaded.genericDeviceNameOID.shouldBeNull()
        loaded.android shouldBe HopliteFixtures.supremeDualPlatform.android
        loaded.ios shouldBe HopliteFixtures.supremeDualPlatform.ios
    }

    "hoplite accepts relaxed kebab-case and snake_case property names" {
        val android = loadYaml<AndroidAttestationConfiguration>(
            """
            applications:
              - package-name: at.asitplus.relaxed-hoplite
                signer_fingerprints:
                  - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
            verification-seconds-offset: 12
            """.trimIndent()
        )

        android.applications.single().packageName shouldBe "at.asitplus.relaxed-hoplite"
        android.applications.single().signerFingerprints.single() shouldBe "NLl2LE1skNSEMZQMV73nMUJYsmQg7A".decodeToByteArray(Base64UrlStrict)
        android.verificationSecondsOffset shouldBe 12

        val supreme = loadYaml<SupremeConfiguration>(
            """
            android:
              applications:
                - package-name: at.asitplus.supreme-relaxed
                  signer_fingerprints:
                    - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
            ios: null
            clock: system
            generic-device-name-oid: 1.2.3.4
            """.trimIndent()
        )

        supreme.android!!.applications.single().packageName shouldBe "at.asitplus.supreme-relaxed"
        supreme.android!!.applications.single().signerFingerprints.single() shouldBe "NLl2LE1skNSEMZQMV73nMUJYsmQg7A".decodeToByteArray(Base64UrlStrict)
        supreme.ios.shouldBeNull()
        supreme.clock shouldBe SupremeConfiguration.Clock.System
        supreme.genericDeviceNameOID.toString() shouldBe "1.2.3.4"
    }

    "hoplite relaxed property casings all load to the same equivalent config" {
        assertHopliteCasingsEquivalent(HopliteFixtures.androidMaximal)
        assertHopliteCasingsEquivalent(HopliteFixtures.iosMaximal)
        assertHopliteCasingsEquivalent(HopliteFixtures.supremeDualPlatform)
    }

    "hoplite rejects missing required values and malformed collection shapes" - {
        "missing required field" {
            shouldThrow<ConfigException> {
                loadYaml<AndroidAttestationConfiguration>(
                    """
                    applications:
                      - packageName: at.asitplus.missing
                    """.trimIndent()
                )
            }
        }

        "wrong collection shape for ios applications" {
            shouldThrow<ConfigException> {
                loadYaml<IosAttestationConfiguration>(
                    """
                    applications: definitely-not-a-list
                    """.trimIndent()
                )
            }
        }

        "wrong nested shape for supreme android applications" {
            shouldThrow<ConfigException> {
                loadYaml<SupremeConfiguration>(
                    """
                    android:
                      applications:
                        packageName: at.asitplus.bad-shape
                    clock: system
                    """.trimIndent()
                )
            }
        }
    }

    "hoplite rejects invalid revocation and clock subtype discriminators" {
        val invalidRevocation = HopliteFixtures.androidMaximal.toYamlString()
            .replace("type: google", "type: definitely-not-a-loader")

        shouldThrow<ConfigException> {
            loadYaml<AndroidAttestationConfiguration>(invalidRevocation)
        }

        val invalidClock = HopliteFixtures.supremeDualPlatform.toYamlString()
            .replace("clock: system", "clock:\n  type: definitely-not-a-clock")

        shouldThrow<ConfigException> {
            loadYaml<SupremeConfiguration>(invalidClock)
        }
    }

    "hoplite rejects null required values and invalid ios version payloads" - {
        "null applications" {
            shouldThrow<ConfigException> {
                loadYaml<IosAttestationConfiguration>(
                    """
                    applications: null
                    """.trimIndent()
                )
            }
        }

        "invalid semver" {
            val invalidIosVersion = HopliteFixtures.iosMaximal.toYamlString()
                .replace("semVer: 17.5.1", "semVer: not-a-semver")

            shouldThrow<ConfigException> {
                loadYaml<IosAttestationConfiguration>(invalidIosVersion)
            }
        }

        "invalid build number" {
            val invalidBuildNumber = HopliteFixtures.iosMaximal.toYamlString()
                .replace("buildNumber: 21F90", "buildNumber: not-a-build")

            shouldThrow<ConfigException> {
                loadYaml<IosAttestationConfiguration>(invalidBuildNumber)
            }
        }
    }

    "hoplite loads multiline pem trust anchors and explicit revocation payloads" {
        val hardwareAnchor = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.first()
        val softwareAnchor = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.first()
        val yaml = """
            applications:
              - packageName: at.asitplus.multiline
                signerFingerprints:
                  - 34b9762c4d6c90d48431940c57bde7314258b26420ec
            hardwareTrustedRoots:
              - |-
${trustedRootPem(hardwareAnchor).prependIndent("                  ")}
            softwareTrustedRoots:
              - |-
${trustedRootPem(softwareAnchor).prependIndent("                  ")}
            revocation:
              - type: mem
                list:
                  entries:
                    deadbeef:
                      status: REVOKED
                      reason: SOFTWARE_FLAW
                    cafebabe:
                      status: SUSPENDED
                      expires: 2026-03-31
                      comment: still suspended
                  expires: 2026-04-01T00:00:00Z
              - type: file
                path: ./localrevocation.json
                fallbackRevocationListValiditySeconds: 123
                fallbackToFileSystemInfo: false
        """.trimIndent()

        val loaded = loadYaml<AndroidAttestationConfiguration>(yaml)

        loaded.hardwareTrustedRoots shouldBe setOf(hardwareAnchor)
        loaded.softwareTrustedRoots shouldBe setOf(softwareAnchor)
        loaded.revocation[0] shouldBe AndroidRevocationList.InMemoryLoader.Configuration(
            AndroidRevocationList(
                entries = mapOf(
                    "deadbeef" to AndroidRevocationList.Entry(
                        status = AndroidRevocationList.RevocationStatus.REVOKED,
                        reason = AndroidRevocationList.RevocationReason.SOFTWARE_FLAW
                    ),
                    "cafebabe" to AndroidRevocationList.Entry(
                        status = AndroidRevocationList.RevocationStatus.SUSPENDED,
                        expires = kotlin.time.Instant.parse("2026-03-31T00:00:00Z"),
                        comment = "still suspended"
                    )
                ),
                expires = kotlin.time.Instant.parse("2026-04-01T00:00:00Z")
            )
        )
        loaded.revocation[1] shouldBe AndroidRevocationList.FileLoader.Configuration(
            path = "./localrevocation.json",
            fallbackRevocationListValiditySeconds = 123,
            fallbackToFileSystemInfo = false
        )
    }
}

private inline fun <reified A : AttestationConfiguration> assertHopliteMatchesCanonical(expected: A) {
    val fromYaml = loadYaml<A>(expected.toYamlString())
    val fromJson = loadJson<A>(expected.toJsonString())

    fromYaml shouldBe expected
    fromJson shouldBe expected
}

private inline fun <reified A : AttestationConfiguration> assertHopliteCasingsEquivalent(expected: A) {
    PropertyCaseStyle.entries.forEach { style ->
        val recasedJson = expected.toJsonElement().recaseKeys(style).toString()
        loadJson<A>(recasedJson) shouldBe expected
    }
}

private inline fun <reified A : AttestationConfiguration> loadYaml(yaml: String): A =
    loadWithHoplite(yaml, ".yaml")

private inline fun <reified A : AttestationConfiguration> loadJson(json: String): A =
    loadWithHoplite(json, ".json")

@OptIn(ExperimentalHoplite::class)
private inline fun <reified A : AttestationConfiguration> loadWithHoplite(contents: String, suffix: String): A {
    val file = File.createTempFile("warden-loader-", suffix)
    return try {
        file.writeText(contents)
        ConfigLoaderBuilder.default()
            .withExplicitSealedTypes()
            .addFileSource(file)
            .addDecoder(decoderFor<A>())
            .build()
            .loadConfigOrThrow<A>()
    } finally {
        file.delete()
    }
}

@Suppress("UNCHECKED_CAST")
private inline fun <reified A : AttestationConfiguration> decoderFor(): Decoder<A> =
    when (A::class) {
        AndroidAttestationConfiguration::class -> AndroidAttestationConfiguration.hopliteDecoder()
        IosAttestationConfiguration::class -> IosAttestationConfiguration.hopliteDecoder()
        SupremeConfiguration::class -> SupremeConfiguration.hopliteDecoder()
        else -> error("Unsupported configuration type ${A::class.qualifiedName}")
    } as Decoder<A>

private object HopliteFixtures {
    val androidMinimal = AndroidAttestationConfiguration(
        singleApp = AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.android-min",
            signerFingerprints = setOf("0a 3e d5 8f d5 39 cb a3 f2 52 aa ab 23 c3 9c 90 e9 08 13 56 cf a6 ad 21 00 3c f7 94 85 61 3a e3".parseHex())
        )
    )

    val androidMaximal = AndroidAttestationConfiguration(
        applications = listOf(
            AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation-client",
                signerFingerprints = setOf(
                    "b0 2d 99 66 b7 02 df 5f 45 21 a4 17 7d 18 39 8f c0 b3 49 4a b1 27 83 a9 3b a9 68 be 07 91 ed 9a".parseHex()
                ),
                appVersion = 42,
                androidVersionOverride = 340000,
                patchLevelOverride = PatchLevel(2025, 3, maxFuturePatchLevelMonths = 2),
                requireRemoteKeyProvisioningOverride = true,
                requireStrongBoxOverride = true,
                verifiedBootKeys = linkedSetOf(
                    VerifiedBootKey.OEM,
                    VerifiedBootKey.Digest(
                        "38 92 38 5f a8 7f f5 8e 33 8d 84 09 f9 61 b8 0b 6a f4 5b 8b c2 b6 ed a3 c2 43 7c 32 cc b6 b0 ec"
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
                "0a 3e d5 8f d5 39 cb a3 f2 52 aa ab 23 c3 9c 90 e9 08 13 56 cf a6 ad 21 00 3c f7 94 85 61 3a e3"
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

private fun trustedRootPem(root: TrustedRoot): String = when (root) {
    is TrustedRoot.Certificate -> root.certificate.toKmpCertificate().getOrThrow().encodeToPem()
    is TrustedRoot.PublicKey -> root.publicKey.toCryptoPublicKey().getOrThrow().encodeToPem()
}

private fun JsonElement.recaseKeys(style: PropertyCaseStyle): JsonElement = when (this) {
    is JsonObject -> JsonObject(entries.associate { (key, value) -> style.recase(key) to value.recaseKeys(style) })
    is JsonArray -> JsonArray(map { it.recaseKeys(style) })
    else -> this
}

private enum class PropertyCaseStyle {
    CAMEL,
    KEBAB,
    SNAKE,
    UPPER_SNAKE;

    fun recase(key: String): String {
        val words = key.splitCamelCase()
        return when (this) {
            CAMEL -> words.first() + words.drop(1).joinToString("") { it.replaceFirstChar(Char::titlecase) }
            KEBAB -> words.joinToString("-")
            SNAKE -> words.joinToString("_")
            UPPER_SNAKE -> words.joinToString("_") { it.uppercase() }
        }
    }
}

private fun String.splitCamelCase(): List<String> =
    replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        .split(Regex("[^A-Za-z0-9]+"))
        .filter(String::isNotBlank)
        .map(String::lowercase)
