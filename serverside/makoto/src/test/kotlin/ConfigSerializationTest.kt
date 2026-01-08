import at.asitplus.attestation.APPLE_DEFAULT_TRUSTED_ROOTS
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.IosAttestationConfiguration.OsVersions
import at.asitplus.attestation.android.*
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val serializationTest by testSuite {
    val androidAttestationConfiguration = AndroidAttestationConfiguration(
        applications = listOf(
            /*(1)!*/AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.attestation_client",
                signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
            ),
            /*(2)!*/AndroidAttestationConfiguration.AppData(
                /*(3)!*/packageName = "at.asitplus.attestation_client-hardened",
                signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex()),
                appVersion = 2,
                /*(4)!*/androidVersionOverride = 160000,
                patchLevelOverride = PatchLevel(
                    year = 2025, month = 9,
                    /*(5)!*/maxFuturePatchLevelMonths = 2
                ),
                /*(6)!*/requireRemoteKeyProvisioningOverride = true,
                /*(7)!*/trustedRootOverrides = setOf(GOOGLE_RKP_EC_ROOT),
                /*(8)!*/requireStrongBoxOverride = true,
            )
        ),
        /*(9)!*/androidVersion = 130000, patchLevel = PatchLevel(2023, 12), requireStrongBox = false,
        allowBootloaderUnlock = false, //DEFAULT
        /*(10)!*/requireRollbackResistance = false, //DEFAULT
        /*(11)!*/ignoreLeafValidity = false, // defaults to true
        hardwareTrustedRoots = GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS, //DEFAULT
        softwareTrustedRoots = GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12, //DEFAULT
        verificationSecondsOffset = 0, //DEFAULT
        /*(12)!*/disableHardwareAttestation = false,
        enableSoftwareAttestation = false, //DEFAULT
        /*(13)!*/enableNougatAttestation = false, //DEFAULT
        /*(14)!*/attestationStatementValiditySeconds = null, // DEFAULT; no validity time checks!
        /*(15)!*/ revocation = listOf(AndroidRevocationList.GoogleDefaultLoaderConfig.withHttpProxy("https://192.168.178.74:8000")), // Defaults to null
        requireRemoteKeyProvisioning = false //DEFAULT

    )

    val iosAttestationConfiguration = IosAttestationConfiguration(
        applications = listOf(
            /*(16)!*/IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644",
                bundleIdentifier = "at.asitplus.attestation-client",
                /*(17)!*/iosVersionOverride = OsVersions("16.0", "20A10"),
                /*(18)!*/sandbox = true, //defaults to false
            )
        ),
        /* Same as 17.0 ↘↘ */
        /*(20)!*/iosVersion = OsVersions("17", "21A36"), //defaults to null (= no version check)
        /*(21)!*/attestationStatementValiditySeconds = 600, //DEFAULT
        /*(22)!*/trustedRoots = APPLE_DEFAULT_TRUSTED_ROOTS //DEFAULT
    )

    "JSON" - {

        "Object" {
            val android = androidAttestationConfiguration.toJsonElement()
            AndroidAttestationConfiguration.fromJsonObject(android) shouldBe androidAttestationConfiguration

            val iOS = iosAttestationConfiguration.toJsonElement()
            IosAttestationConfiguration.fromJsonObject(iOS) shouldBe iosAttestationConfiguration
        }

        "String" {
            val androidJson = androidAttestationConfiguration.toJsonString()
            AndroidAttestationConfiguration.fromJsonString(androidJson) shouldBe androidAttestationConfiguration

            val androidYaml = androidAttestationConfiguration.toYamlString()
            println(androidYaml)
            AndroidAttestationConfiguration.fromYamlString(androidYaml) shouldBe androidAttestationConfiguration

            val iosJson = iosAttestationConfiguration.toJsonString()
            IosAttestationConfiguration.fromYamlString(iosJson) shouldBe iosAttestationConfiguration

            val iosYaml = iosAttestationConfiguration.toYamlString()
            IosAttestationConfiguration.fromYamlString(iosYaml) shouldBe iosAttestationConfiguration
        }

    }
}