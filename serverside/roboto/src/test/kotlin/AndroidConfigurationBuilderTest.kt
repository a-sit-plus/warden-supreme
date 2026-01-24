import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.GOOGLE_RKP_EC_ROOT
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
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
            signerFingerprints = listOf(ByteArray(32) { 2 })
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
            .enableNougatAttestation()
            .revocation(revocation)
            .requireRemoteKeyProvisioning(true)
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
        config.enableNougatAttestation shouldBe true
        config.revocation shouldBe revocation
        config.requireRemoteKeyProvisioning shouldBe true
    }
}
