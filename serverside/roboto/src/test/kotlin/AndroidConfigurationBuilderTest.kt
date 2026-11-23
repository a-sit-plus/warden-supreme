import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration.TrustedRootOverrides
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
import at.asitplus.attestation.android.GOOGLE_RKP_EC_ROOT
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

val AndroidConfigurationBuilderTests by matrixSuite {
    data("TEE underclaim configuration", listOf(false, true)) test { allow ->
        val app = AndroidAttestationConfiguration.AppData("com.example", setOf(ByteArray(32) { 1 }))
        val baseline = AndroidAttestationConfiguration(listOf(app), revocation = emptyList())
        baseline.allowTeeSecurityLevelForStrongbox shouldBe false
        val expected = baseline.copy(allowTeeSecurityLevelForStrongbox = allow)
        val configurations = listOf(
            AndroidAttestationConfiguration(listOf(app), revocation = emptyList(), allowTeeSecurityLevelForStrongbox = allow),
            AndroidAttestationConfiguration(singleApp = app, revocation = emptyList(), allowTeeSecurityLevelForStrongbox = allow),
            AndroidAttestationConfiguration(apps = listOf(app), revocation = emptyList(), allowTeeSecurityLevelForStrongbox = allow),
            AndroidAttestationConfiguration.Builder(app).revocation(emptyList()).allowTeeSecurityLevelForStrongbox(allow).build(),
            AndroidAttestationConfiguration.Builder(listOf(app)).revocation(emptyList()).allowTeeSecurityLevelForStrongbox(allow).build(),
        )
        configurations.forEach { config ->
            config.allowTeeSecurityLevelForStrongbox shouldBe allow
            config.toString() shouldContain "allowTeeSecurityLevelForStrongbox=$allow"
            AndroidAttestationConfiguration.fromJsonString(config.toJsonString()) shouldBe config
            AndroidAttestationConfiguration.fromYamlString(config.toYamlString()) shouldBe config
        }
        if (allow) {
            expected shouldNotBe baseline
            expected.hashCode() shouldNotBe baseline.hashCode()
        } else {
            expected.toJsonString() shouldNotContain "allowTeeSecurityLevelForStrongbox"
            expected.toYamlString() shouldNotContain "allowTeeSecurityLevelForStrongbox"
        }
    }

    "Java constructor overload and builders keep the strict default" {
        val app = AndroidAttestationConfiguration.AppData("com.example", setOf(byteArrayOf(1)))
        AndroidAttestationConfiguration::class.java.getConstructor(List::class.java)
            .newInstance(listOf(app)).allowTeeSecurityLevelForStrongbox shouldBe false
        AndroidAttestationConfiguration.Builder(app).build().allowTeeSecurityLevelForStrongbox shouldBe false
        AndroidAttestationConfiguration(singleApp = app).allowTeeSecurityLevelForStrongbox shouldBe false
        AndroidAttestationConfiguration(apps = listOf(app)).allowTeeSecurityLevelForStrongbox shouldBe false
    }

    "TrustedRootOverrides accepts one hardware root with default, null or explicit software roots" {
        val hardware = GOOGLE_RKP_EC_ROOT
        val software = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
        val hardwareOnly = TrustedRootOverrides(hardware = setOf(hardware))
        val both = TrustedRootOverrides(setOf(hardware), software)

        TrustedRootOverrides(hardware) shouldBe hardwareOnly
        TrustedRootOverrides(hardware = hardware) shouldBe hardwareOnly
        TrustedRootOverrides(hardware, null) shouldBe hardwareOnly
        TrustedRootOverrides(hardware, software) shouldBe both
        TrustedRootOverrides(hardware = hardware, software = software) shouldBe both
        shouldThrow<IllegalArgumentException> { TrustedRootOverrides(hardware, emptySet()) }
    }

    "TrustedRootOverrides accepts one software root with default, null or explicit hardware roots" {
        val hardware = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
        val software = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.first()
        val softwareOnly = TrustedRootOverrides(software = setOf(software))
        val both = TrustedRootOverrides(hardware, setOf(software))

        TrustedRootOverrides(software = software) shouldBe softwareOnly
        TrustedRootOverrides(null, software) shouldBe softwareOnly
        TrustedRootOverrides(hardware, software) shouldBe both
        TrustedRootOverrides(hardware = hardware, software = software) shouldBe both
        shouldThrow<IllegalArgumentException> { TrustedRootOverrides(emptySet(), software) }
    }

    "TrustedRootOverrides still accepts set and null arguments" {
        val hardware = setOf(GOOGLE_RKP_EC_ROOT)
        val software = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
        val inherited = TrustedRootOverrides()

        TrustedRootOverrides(null) shouldBe inherited
        TrustedRootOverrides(hardware = null) shouldBe inherited
        TrustedRootOverrides(software = null) shouldBe inherited
        TrustedRootOverrides(null, null) shouldBe inherited
        TrustedRootOverrides(hardware = null, software = null) shouldBe inherited
        TrustedRootOverrides(hardware, null) shouldBe TrustedRootOverrides(hardware = hardware)
        TrustedRootOverrides(null, software) shouldBe TrustedRootOverrides(software = software)
    }

    "Android AppData builder applies overrides" {
        val signer = ByteArray(32) { it.toByte() }
        val patch = PatchLevel(2024, 2)
        val publicKey = GOOGLE_RKP_EC_ROOT.publicKey
        val overrides = TrustedRootOverrides(
            hardware = setOf(TrustedRoot.PublicKey(publicKey)),
            software = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12,
        )
        val app = AndroidAttestationConfiguration.AppData.Builder("com.example", signer)
            .appVersion(5)
            .androidVersionOverride(150000)
            .patchLevelOverride(patch)
            .trustedRootOverrides(overrides)
            .requireRemoteProvisioningOverride(true)
            .requireStrongBoxOverride(true)
            .build()

        app.packageName shouldBe "com.example"
        app.signerFingerprints.single().contentEquals(signer) shouldBe true
        app.appVersion shouldBe 5
        app.androidVersionOverride shouldBe 150000
        app.patchLevelOverride shouldBe patch
        app.requireRemoteKeyProvisioningOverride shouldBe true
        app.requireStrongBoxOverride shouldBe true
        app.trustedRootOverrides shouldBe overrides

        val config = AndroidAttestationConfiguration(listOf(app), enableSoftwareAttestation = true)
        val encodedApp = config.toJsonElement().getValue("applications").jsonArray.single().jsonObject
        (encodedApp["trustedRootOverrides"] as JsonObject).keys shouldBe setOf("hardware", "software")
        AndroidAttestationConfiguration.fromJsonString(config.toJsonString()) shouldBe config
        AndroidAttestationConfiguration.fromYamlString(config.toYamlString()) shouldBe config
    }

    "Legacy trust roots round-trip for one engine and are rejected in mixed mode" {
        val roots = setOf(GOOGLE_RKP_EC_ROOT)
        @Suppress("DEPRECATION")
        val app = AndroidAttestationConfiguration.AppData.Builder("com.example", ByteArray(32) { 1 })
            .trustedRootOverrides(roots)
            .build()
        @Suppress("DEPRECATION")
        app.deprecatedSecurityLevelUnawareTrustedRootOverrides shouldBe roots
        val configuration = AndroidAttestationConfiguration(listOf(app))
        listOf(configuration, configuration.copy(disableHardwareAttestation = true, enableSoftwareAttestation = true))
            .forEach { config ->
                val encodedApp = config.toJsonElement().getValue("applications").jsonArray.single().jsonObject
                (encodedApp["trustedRootOverrides"] is JsonArray) shouldBe true
                encodedApp.keys.any { it.startsWith("deprecatedSecurity") } shouldBe false
                AndroidAttestationConfiguration.fromJsonString(config.toJsonString()) shouldBe config
                AndroidAttestationConfiguration.fromYamlString(config.toYamlString()) shouldBe config
            }
        shouldThrow<AndroidAttestationException> {
            configuration.copy(enableSoftwareAttestation = true)
        }.message.orEmpty() shouldContain "single attestation engine"
        shouldThrow<IllegalArgumentException> {
            app.copy(trustedRootOverrides = TrustedRootOverrides())
        }.message.orEmpty() shouldContain "Use one form of trustedRootOverrides"
    }

    "Empty trust root overrides inherit global roots in JSON and YAML" {
        val signer = "01".repeat(32)
        fun json(overrides: String) = """
            {"applications": [{"packageName": "com.example", "signerFingerprints": ["$signer"], "trustedRootOverrides": $overrides}]}
        """.trimIndent()
        fun yaml(overrides: String) = """
            applications:
              - packageName: com.example
                signerFingerprints: ["$signer"]
                trustedRootOverrides: $overrides
        """.trimIndent()

        val cases = listOf(
            "null" to null,
            "[]" to null,
            "{}" to TrustedRootOverrides(),
            """{"hardware": [], "software": null}""" to TrustedRootOverrides(),
        )
        for ((overrides, expected) in cases) {
            val fromJson = AndroidAttestationConfiguration.fromJsonString(json(overrides)).applications.single()
            val fromYaml = AndroidAttestationConfiguration.fromYamlString(yaml(overrides)).applications.single()
            fromJson.trustedRootOverrides shouldBe expected
            fromYaml shouldBe fromJson
        }
        shouldThrow<SerializationException> {
            AndroidAttestationConfiguration.fromJsonString(json("""{"hardwrae": []}"""))
        }.message.orEmpty() shouldContain "hardwrae"
        shouldThrow<IllegalArgumentException> { TrustedRootOverrides(hardware = emptySet()) }
    }

    "Android configuration builder sets fields" {
        val app = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = setOf(ByteArray(32) { 2 })
        )
        val hardwareRoots = setOf(GOOGLE_RKP_EC_ROOT)
        val softwareRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.take(1).toSet()
        val revocation = listOf(
            AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("http://localhost:8080")
        )

        val config = AndroidAttestationConfiguration.Builder(app)
            .androidVersion(140000)
            .patchLevel(PatchLevel(2024, 3))
            .requireStrongBox()
            .allowBootloaderUnlock()
            .requireRollbackResistance()
            .enforceLeafValidity()
            .hardwareTrustedRoots(hardwareRoots)
            .softwareTrustedRoots(softwareRoots)
            .verificationSecondsOffset(123)
            .attestationStatementValiditySeconds(600)
            .disableHardwareAttestation()
            .enableSoftwareAttestation()
            .revocation(revocation)
            .requireRemoteKeyProvisioning(true)
            .enforceFactoryProvisionedChainValidity(false)
            .build()

        config.androidVersion shouldBe 140000
        config.patchLevel shouldBe PatchLevel(2024, 3)
        config.requireStrongBox shouldBe true
        config.allowBootloaderUnlock shouldBe true
        config.requireRollbackResistance shouldBe true
        config.ignoreLeafValidity shouldBe false
        config.hardwareTrustedRoots shouldBe hardwareRoots
        config.softwareTrustedRoots shouldBe softwareRoots
        config.verificationSecondsOffset shouldBe 123
        config.attestationStatementValiditySeconds shouldBe 600
        config.disableHardwareAttestation shouldBe true
        config.enableSoftwareAttestation shouldBe true
        config.revocation shouldBe revocation
        config.requireRemoteKeyProvisioning shouldBe true
        config.enforceFactoryProvisionedChainValidity shouldBe false
    }

    "Android configuration alternative constructors propagate factory-provisioned chain validity checks" {
        val app = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = setOf(ByteArray(32) { 3 })
        )

        AndroidAttestationConfiguration(
            singleApp = app,
            enforceFactoryProvisionedChainValidity = false
        ).enforceFactoryProvisionedChainValidity shouldBe false

        AndroidAttestationConfiguration(
            apps = listOf(app),
            enforceFactoryProvisionedChainValidity = false
        ).enforceFactoryProvisionedChainValidity shouldBe false
    }

    "AppData equality is content-based for byte arrays and order-sensitive for lists" {
        val digestA1 = byteArrayOf(1, 2, 3)
        val digestA2 = byteArrayOf(1, 2, 3)
        val digestB1 = byteArrayOf(4, 5, 6)
        val digestB2 = byteArrayOf(4, 5, 6)
        val bootDigest1 = VerifiedBootKey.Digest(byteArrayOf(9, 9, 9))
        val bootDigest2 = VerifiedBootKey.Digest(byteArrayOf(9, 9, 9))

        val first = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = setOf(digestA1, digestB1),
            verifiedBootKeys = linkedSetOf(VerifiedBootKey.OEM, bootDigest1)
        )
        val sameContent = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = setOf(digestA2, digestB2),
            verifiedBootKeys = linkedSetOf(bootDigest2, VerifiedBootKey.OEM)
        )

        (first == sameContent) shouldBe true
        first.hashCode() shouldBe sameContent.hashCode()
    }

    "AndroidAttestationConfiguration compares byte-array sets by content regardless of set iteration order" {
        val app = AndroidAttestationConfiguration.AppData(
            packageName = "com.example",
            signerFingerprints = setOf(byteArrayOf(7, 8, 9))
        )
        val configA = AndroidAttestationConfiguration(
            applications = listOf(app),
            hardwareTrustedRoots = setOf(GOOGLE_RKP_EC_ROOT),
            softwareTrustedRoots = setOf(GOOGLE_RKP_EC_ROOT),
            revocation = emptyList(),
            verifiedBootKeys = linkedSetOf(
                VerifiedBootKey.OEM,
                VerifiedBootKey.Digest(byteArrayOf(1)),
                VerifiedBootKey.Digest(byteArrayOf(2))
            )
        )
        val configB = AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = "com.example",
                    signerFingerprints = setOf(byteArrayOf(7, 8, 9))
                )
            ),
            hardwareTrustedRoots = setOf(GOOGLE_RKP_EC_ROOT),
            softwareTrustedRoots = setOf(GOOGLE_RKP_EC_ROOT),
            revocation = emptyList(),
            verifiedBootKeys = linkedSetOf(
                VerifiedBootKey.Digest(byteArrayOf(2)),
                VerifiedBootKey.OEM,
                VerifiedBootKey.Digest(byteArrayOf(1))
            )
        )

        (configA == configB) shouldBe true
        configA.hashCode() shouldBe configB.hashCode()
    }
}
