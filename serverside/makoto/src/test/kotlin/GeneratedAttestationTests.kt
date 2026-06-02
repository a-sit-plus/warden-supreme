@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.attestation.android.closestToRoot
import at.asitplus.attestation.android.closestToRootOrNull
import at.asitplus.attestation.android.contentHashCodeIfArray
import at.asitplus.attestation.android.hasAndroidKeystoreAttestation
import at.asitplus.attestation.data.AttestationCreator
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.ExperimentalTime

val GeneratedAttestationTests by testSuite {

    val challenge = "42".encodeToByteArray()
    val packageName = "fa.ke.it.till.you.make.it"
    val signatureDigest = Random.nextBytes(32)
    val appVersion = 5
    val androidVersion = 11

    val attestationProof = AttestationCreator.createAttestation(
        challenge,
        packageName,
        signatureDigest,
        appVersion,
        androidVersion
    )

    fun prependForgedAttestationLeaf(chain: List<X509Certificate>): List<X509Certificate> {
        val attestationLeaf = chain.first()
        val forgedKeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
        val now = Date()
        val forgedLeaf = X509v3CertificateBuilder(
            X500Name("CN=Forged Issuer"),
            BigInteger.valueOf(Random.nextLong()),
            now,
            Date(now.time + 60_000L),
            X500Name("CN=Forged Subject"),
            SubjectPublicKeyInfo.getInstance(forgedKeyPair.public.encoded)
        ).addExtension(
            ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
            false,
            ASN1OctetString.getInstance(
                attestationLeaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
            ).octets
        ).build(
            JcaContentSignerBuilder("SHA256withECDSA").build(forgedKeyPair.private)
        ).encoded.let {
            CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()) as X509Certificate
        }

        return listOf(forgedLeaf) + chain
    }

    val attestationService = Makoto(
        androidAttestationConfiguration = AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = packageName,
                    signerFingerprints = setOf(signatureDigest),
                    appVersion = appVersion
                )
            ),
            androidVersion = androidVersion,
            patchLevel = PatchLevel(2021, 8),
            requireStrongBox = false,
            allowBootloaderUnlock = false,
            ignoreLeafValidity = false,
            hardwareTrustedRoots = setOf(TrustedRoot( attestationProof.last()))
        ),
        iosAttestationConfiguration = IosAttestationConfiguration(
            applications = listOf(
                IosAttestationConfiguration.AppData(
                    teamIdentifier = "9CYHJNG644",
                    bundleIdentifier = "at.asitplus.attestation-client"
                )
            )
        ),
        verificationTimeOffset = Duration.ZERO
    )

    "Generated Attestation Test" {
        attestationService.verifyAttestation(attestationProof = attestationProof.map { it.encoded }, challenge)
            .shouldBeInstanceOf<AttestationResult.Android.Verified>().attestationCertificateClosestToRoot shouldBe attestationProof.first()

        val dbg = attestationService.collectDebugInfo(attestationProof.map { it.encoded }, challenge).serialize()

        WardenDebugAttestationStatement.deserialize(dbg).replayGenericAttestation()
            .shouldBeInstanceOf<AttestationResult.Android.Verified>().attestationCertificateClosestToRoot shouldBe attestationProof.first()
    }

    "Android result surfaces attestation certificate closest to root" {
        val forgedChain = prependForgedAttestationLeaf(attestationProof)
        val result = AttestationResult.Android.Verified(forgedChain)

        forgedChain.closestToRootOrNull { it.hasAndroidKeystoreAttestation }!!.encoded shouldBe attestationProof.first().encoded

        result.isLeafAttestationCertificate shouldBe false
        result.attestationCertificateClosestToRoot shouldBe attestationProof.first()
        result.androidAttestationExtension.attestationChallenge shouldBe challenge
    }

    "Android key binding requires attestation on the leaf certificate" {
        val normal = AttestationResult.Android.Verified(attestationProof)
        normal.isLeafAttestationCertificate shouldBe true
        normal.requireLeafAttestationCertificateForKeyBinding().getOrThrow() shouldBe attestationProof.first()

        val forged = AttestationResult.Android.Verified(prependForgedAttestationLeaf(attestationProof))
        forged.requireLeafAttestationCertificateForKeyBinding()
            .exceptionOrNull()
            .shouldBeInstanceOf<AttestationException.Content.Android>()
    }

}
