package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import kotlin.time.Duration
import kotlin.time.Instant

val DebugStatementSerializationRegressionTests by matrixSuite {

    "WardenDebugAttestationStatement.serializeCompact does not crash (TrustedRootSerializer init)" {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
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
            version = wardenVersion,
        )

        val compact = statement.serializeCompact()
        WardenDebugAttestationStatement.deserializeCompact(compact) shouldBe statement
    }
}
