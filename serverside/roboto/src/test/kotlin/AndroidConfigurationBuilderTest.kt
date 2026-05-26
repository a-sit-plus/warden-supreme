import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.GOOGLE_RKP_EC_ROOT
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val AndroidConfigurationBuilderTests by testSuite {
    "Android AppData builder applies overrides" {
        val signer = ByteArray(32) { it.toByte() }
        val patch = PatchLevel(2024, 2)
        val publicKey = GOOGLE_RKP_EC_ROOT.publicKey
        val app = AndroidAttestationConfiguration.AppData.Builder("com.example", signer)
            .appVersion(5)
            .androidVersionOverride(150000)
            .patchLevelOverride(patch)
            .trustedRootOverrides(setOf(publicKey))
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
        app.trustedRootOverrides shouldBe setOf(TrustedRoot.PublicKey(publicKey))
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
