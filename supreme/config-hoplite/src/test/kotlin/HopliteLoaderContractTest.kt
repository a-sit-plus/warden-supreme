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
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toKmpCertificate
import com.sksamuel.hoplite.ConfigException
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addFileSource
import com.sksamuel.hoplite.decoder.Decoder
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldBeNull
import java.io.File

@OptIn(ExperimentalHoplite::class)
val HopliteLoaderContractTest by testSuite {
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
                  - NLl2LE1skNSEMZQMV73nMUJYsmQg7A
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

private fun trustedRootPem(root: TrustedRoot): String = when (root) {
    is TrustedRoot.Certificate -> root.certificate.toKmpCertificate().getOrThrow().encodeToPEM().getOrThrow()
    is TrustedRoot.PublicKey -> root.publicKey.toCryptoPublicKey().getOrThrow().encodeToPEM().getOrThrow()
}
