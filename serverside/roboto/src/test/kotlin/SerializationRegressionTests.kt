package at.asitplus.attestation.android

import at.asitplus.attestation.wardenVersion
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import java.util.Date
import kotlin.time.Clock

val SerializationRegressionTests by matrixSuite {

    "AndroidDebugAttestationStatement can be serialized (TrustedRootSerializer init)" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val trustedRoot = TrustedRoot.PublicKey(keyPair.public)

        val configuration = AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = "at.asitplus.test",
                    signerFingerprints = setOf(ByteArray(32))
                )
            ),
            hardwareTrustedRoots = setOf(trustedRoot),
            softwareTrustedRoots = setOf(trustedRoot),
            revocation = emptyList(),
        )

        val statement = AndroidDebugAttestationStatement(
            version = wardenVersion,
            configuration = configuration,
            verificationTime = Clock.System.now(),
            challenge = ByteArray(16),
            attestationStatement = emptyList(),
            revocationLists = emptyList(),
        )

        val compact = statement.serializeCompact()
        val decoded = AndroidDebugAttestationStatement.deserializeCompact(compact)
        decoded.version shouldBe wardenVersion
    }

    "Roboto retains at most 100 revocation snapshots and consumes matches" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val trustedRoot = TrustedRoot.PublicKey(keyPair.public)
        val roboto = Roboto(
            AndroidAttestationConfiguration(
                applications = listOf(
                    AndroidAttestationConfiguration.AppData(
                        packageName = "at.asitplus.test",
                        signerFingerprints = setOf(ByteArray(32)),
                    )
                ),
                hardwareTrustedRoots = setOf(trustedRoot),
                softwareTrustedRoots = setOf(trustedRoot),
                revocation = emptyList(),
            )
        )
        val revocationList = AndroidRevocationList(emptyMap())
        val snapshot = listOf(
            ConfigWithList(AndroidRevocationList.InMemoryLoader.Configuration(revocationList), revocationList)
        )

        repeat(101) { roboto.rememberRevocationLists(byteArrayOf(it.toByte()), snapshot) }

        roboto.revocationListsForChallenge(byteArrayOf(0)) shouldBe emptyList()
        roboto.revocationListsForChallenge(byteArrayOf(1)) shouldBe snapshot
        roboto.revocationListsForChallenge(byteArrayOf(1)) shouldBe emptyList()
        roboto.revocationListsForChallenge(byteArrayOf(127)) shouldBe emptyList()
    }
}
