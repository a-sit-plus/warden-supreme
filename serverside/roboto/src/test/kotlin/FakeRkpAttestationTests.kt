package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.data.FakeAttestations
import at.asitplus.attestation.data.SecurityLevel
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import javax.security.auth.x500.X500Principal

/**
 * Fake attestations in the *remotely provisioned* chain shape, which the old test-only generator could
 * not produce: `root -> Droid CA2 -> Droid CA3 -> attestation -> leaf`, all issued by the generator module.
 *
 * The shape is what a verifier reads: `Droid CA2, O=Google LLC` right below the root marks the chain as
 * remotely provisioned, and the attestation certificate's `O` states the security level -- unlike a
 * factory-provisioned chain, which encodes it as a `title` and only ever spells out StrongBox.
 */
val FakeRkpAttestationTests by matrixSuite {

    val challenge = "42".encodeToByteArray()
    val packageName = "fa.ke.it.till.you.make.it"
    val signatureDigest = kotlin.random.Random.nextBytes(32)
    val appVersion = 5
    val androidVersion = 11
    val patchLevel = PatchLevel(2021, 8)

    fun fakeRkpChain(securityLevel: SecurityLevel = SecurityLevel.TEE) = FakeAttestations.createAttestation(
        challenge = challenge,
        packageName = packageName,
        signatureDigest = signatureDigest,
        appVersion = appVersion,
        androidVersion = androidVersion,
        androidPatchLevel = patchLevel.asSingleInt,
        securityLevel = securityLevel,
        provisioning = Provisioning.RKP,
    )

    "the chain has the shape a verifier recognises as remotely provisioned" {
        val chain = fakeRkpChain()

        chain.size shouldBe 5 // leaf, attestation, Droid CA3, Droid CA2, root
        chain.isRemoteKeyProvisioned() shouldBe true
        chain[chain.size - 2].subjectX500Principal.getName(X500Principal.RFC1779) shouldContain "Droid CA2"
        chain[1].subjectX500Principal.getName(X500Principal.RFC1779) shouldContain "TEE"
        // A factory-provisioned chain of the same security level is a different shape entirely.
        FakeAttestations.createAttestation(
            challenge = challenge,
            packageName = packageName,
            signatureDigest = signatureDigest,
            appVersion = appVersion,
            androidVersion = androidVersion,
            androidPatchLevel = patchLevel.asSingleInt,
        ).isRemoteKeyProvisioned() shouldBe false
    }

    data("supreme Parser", listOf(false, true), nameFn = { _, value -> "supreme Parser = $value" }) - { supreme ->

        fun checkerFor(
            chain: List<java.security.cert.X509Certificate>,
            requireStrongBox: Boolean = false,
            requireRemoteKeyProvisioning: Boolean = true,
        ) = Roboto(
            AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData(
                    packageName = packageName,
                    signerFingerprints = setOf(signatureDigest),
                    appVersion = appVersion
                ),
                androidVersion = androidVersion,
                patchLevel = patchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = false,
                ignoreLeafValidity = false,
                hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(chain.last().publicKey)),
                requireRemoteKeyProvisioning = requireRemoteKeyProvisioning,
                supremeParser = supreme
            )
        )

        "a remotely provisioned chain satisfies requireRemoteKeyProvisioning" {
            val chain = fakeRkpChain()

            checkerFor(chain).verify(
                certificates = chain,
                expectedChallenge = challenge
            ).getOrThrow() shouldBe chain
        }

        "a factory-provisioned chain does not" {
            val chain = FakeAttestations.createAttestation(
                challenge = challenge,
                packageName = packageName,
                signatureDigest = signatureDigest,
                appVersion = appVersion,
                androidVersion = androidVersion,
                androidPatchLevel = patchLevel.asSingleInt,
            )

            shouldThrow<AttestationValueException> {
                checkerFor(chain).verify(
                    certificates = chain,
                    expectedChallenge = challenge
                ).getOrThrow()
            }.reason shouldBe AttestationValueException.Reason.SEC_LEVEL
        }

        "a StrongBox chain states its security level on the attestation certificate" {
            val chain = fakeRkpChain(SecurityLevel.STRONGBOX)

            chain[1].subjectX500Principal.getName(X500Principal.RFC1779) shouldContain "StrongBox"
            checkerFor(chain, requireStrongBox = true).verify(
                certificates = chain,
                expectedChallenge = challenge
            ).getOrThrow() shouldBe chain
        }

        "a TEE chain does not pass for StrongBox" {
            val chain = fakeRkpChain(SecurityLevel.TEE)

            shouldThrow<AttestationValueException> {
                checkerFor(chain, requireStrongBox = true).verify(
                    certificates = chain,
                    expectedChallenge = challenge
                ).getOrThrow()
            }.reason shouldBe AttestationValueException.Reason.SEC_LEVEL
        }

        "remote provisioning is not required by default" {
            val chain = fakeRkpChain()

            checkerFor(chain, requireRemoteKeyProvisioning = false).verify(
                certificates = chain,
                expectedChallenge = challenge
            ).getOrThrow() shouldBe chain
        }
    }
}
