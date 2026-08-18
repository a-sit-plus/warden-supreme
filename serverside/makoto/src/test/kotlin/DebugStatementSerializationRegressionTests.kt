package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.ConfigWithList
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import kotlin.time.Duration
import kotlin.time.Instant

val DebugStatementSerializationRegressionTests by matrixSuite {

    "WardenDebugAttestationStatement.serializeCompact does not crash (TrustedRootSerializer init)" {
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

        val revocationList = AndroidRevocationList(
            mapOf(
                "1234" to AndroidRevocationList.Entry(
                    AndroidRevocationList.RevocationStatus.REVOKED,
                    AndroidRevocationList.RevocationReason.KEY_COMPROMISE,
                )
            )
        )
        val statement = WardenDebugAttestationStatement(
            method = WardenDebugAttestationStatement.Method.LEGACY,
            androidAttestationConfiguration = configuration,
            iosAttestationConfiguration = null,
            genericAttestationProof = null,
            keyAttestation = null,
            challenge = null,
            clientData = null,
            verificationTime = Instant.fromEpochMilliseconds(0),
            verificationTimeOffset = Duration.ZERO,
            revocationLists = listOf(
                ConfigWithList(AndroidRevocationList.InMemoryLoader.Configuration(revocationList), revocationList)
            ),
            version = wardenVersion,
        )

        val compact = statement.serializeCompact()
        val decoded = WardenDebugAttestationStatement.deserializeCompact(compact)
        decoded shouldBe statement
        val replayConfiguration = decoded.createWarden().androidAttestationConfiguration!!
        replayConfiguration.revocation.size shouldBe 1
        replayConfiguration.revocation.single().createLoader().loadBlocking(Instant.DISTANT_FUTURE) shouldBe revocationList
    }
}
