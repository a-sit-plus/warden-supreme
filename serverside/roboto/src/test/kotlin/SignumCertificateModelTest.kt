package at.asitplus.attestation.android

import at.asitplus.attestation.data.FakeAttestations
import at.asitplus.attestation.data.SecurityLevel
import at.asitplus.attestation.data.attestationCertChain
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import java.util.Date
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

val SignumCertificateModelTest by matrixSuite {
    val issuedAt = Instant.parse("2025-01-10T00:00:00Z")
    val challenge = byteArrayOf(1, 2, 3, 4)
    val signerDigest = ByteArray(32) { 1 }

    data("provisioning", Provisioning.entries) - { provisioning ->
        val javaChain = FakeAttestations.createAttestation(
            challenge = challenge, packageName = "model.test", signatureDigest = signerDigest,
            creationTime = Date(issuedAt.toEpochMilliseconds()), securityLevel = SecurityLevel.STRONGBOX,
            provisioning = provisioning,
        )
        val chain = javaChain.map { it.toKmpCertificate() }

        "native trust roots retain Java identity and wire format" {
            val roots = listOf(
                TrustedRoot.Certificate(chain.last(), false) to TrustedRoot.Certificate(javaChain.last(), false),
                TrustedRoot.PublicKey(chain.last().publicKey, chain.last().tbsCertificate.subjectName, false) to
                    TrustedRoot.PublicKey(javaChain.last().publicKey, javaChain.last().subjectX500Principal, false),
            )
            roots.forEach { (native, java) ->
                native shouldBe java
                native.hashCode() shouldBe java.hashCode()
                Json.encodeToString<TrustedRoot>(native) shouldBe Json.encodeToString<TrustedRoot>(java)
            }
        }

        "native and Java failure constructors retain certificate bytes and identity" {
            val native = CertificateInvalidException("invalid", certificateChain = chain,
                invalidCertificate = chain.first(), reason = CertificateInvalidException.Reason.TRUST)
            val java = CertificateInvalidException("invalid", certificateChain = javaChain,
                invalidCertificate = javaChain.first(), reason = CertificateInvalidException.Reason.TRUST)
            native shouldBe java
            native.hashCode() shouldBe java.hashCode()
            native.certificateChain.map { it.asn1.toDer().toHexString() } shouldBe javaChain.map { it.encoded.toHexString() }
            native.invalidCertificate!!.asn1.toDer() shouldBe javaChain.first().encoded
        }

        data("supreme parser", listOf(false, true)) - { supremeParser ->
            val verifier = Roboto(AndroidAttestationConfiguration(
                applications = listOf(AndroidAttestationConfiguration.AppData("model.test", setOf(signerDigest))),
                hardwareTrustedRoots = setOf(TrustedRoot.Certificate(chain.last())),
                requireStrongBox = true, requireRemoteKeyProvisioning = provisioning == Provisioning.RKP,
                ignoreLeafValidity = false, enforceFactoryProvisionedChainValidity = true,
                revocation = emptyList(), supremeParser = supremeParser,
            ))

            "native and Java verification return the original chains" {
                verifier.verify(chain, issuedAt + 10.seconds, challenge).getOrThrow() shouldBe chain
                verifier.verify(javaChain, issuedAt + 10.seconds, challenge).getOrThrow() shouldBe javaChain
            }

            "native and Java debug statements serialize identically and replay" {
                val native = verifier.collectDebugInfo(chain, challenge, issuedAt + 10.seconds)
                val java = verifier.collectDebugInfo(javaChain, challenge, issuedAt + 10.seconds)
                native.serialize() shouldBe java.serialize()
                val replayed = AndroidDebugAttestationStatement.deserializeCompact(native.serializeCompact()).replay().getOrThrow()
                replayed.map { it.asn1.toDer().toHexString() } shouldBe javaChain.map { it.encoded.toHexString() }
            }
        }
    }

    data("captured provisioning metadata", listOf(sammy14, pixel6KeyMint200Good), nameFn = { it.name }) test { fixture ->
        val java = fixture.attestationCertChain
        val native = java.map { it.toKmpCertificate() }
        native.isRemoteKeyProvisioned() shouldBe java.isRemoteKeyProvisioned()
        native.getRkpData() shouldBe java.getRkpData()
        native.getNumberOfRemotelyProvisionedCertificates() shouldBe java.getNumberOfRemotelyProvisionedCertificates()
    }
}
