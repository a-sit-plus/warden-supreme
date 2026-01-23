@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate as SignumX509Certificate
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate as JcaX509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlin.text.HexFormat
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private data class E2eCase(
    val name: String,
    val attestationResource: String,
    val nonceHex: String,
)

private val e2eCases = listOf(
    E2eCase(
        name = "android",
        attestationResource = "aksattest.json",
        nonceHex = "CAC4307080875C418BEB668E825649DC",
    ),
    E2eCase(
        name = "ios",
        attestationResource = "ios-appattest.json",
        nonceHex = "D4BD9EFC2A1AB1E2351143A4E67BB91F",
    ),
)

private val fixedClock = FixedTimeClock(2024u, 10u, 1u)
private val verificationOffset = 12.hours + 45.minutes
private val fakeAndroidPackage = "com.example.fake.android"
private val fakeAndroidSignerDigest = MessageDigest.getInstance("SHA-256")
    .digest("fake-signer".encodeToByteArray())

private val androidConfig = AndroidAttestationConfiguration.Builder(
    AndroidAttestationConfiguration.AppData(
        packageName = "at.asitplus.cryptotest.androidApp",
        signerFingerprints = listOf(
            "941A4513A3027563D3A6EA48EEE85BA45EB9F69CEEA19EF0EBB17F100BFC8878"
                .hexToByteArray(HexFormat.UpperCase)
        ),
    )
)
    .enforceLeafValidity()
    .attestationStatementValiditySeconds(300)
    .build()

private val iosConfig = IosAttestationConfiguration(
    IosAttestationConfiguration.AppData(
        teamIdentifier = "9CYHJNG644",
        bundleIdentifier = "at.asitplus.signumtest.iosApp",
        sandbox = true,
    )
)

private val makoto = Makoto(
    androidAttestationConfiguration = androidConfig,
    iosAttestationConfiguration = iosConfig,
    clock = fixedClock,
    verificationTimeOffset = verificationOffset,
)

private fun verifierForNonce(nonce: ByteArray, challengeValidator: ChallengeValidator = InMemoryChallengeCache(
    fixedClock,
    -verificationOffset
)): AttestationVerifier = AttestationVerifier(
    makoto = makoto,
    nonceGenerator = suspend { nonce },
    challengeValidator = challengeValidator,
)

private fun verifierForNonce(
    makoto: Makoto,
    nonce: ByteArray,
    challengeValidator: ChallengeValidator = InMemoryChallengeCache(
        makoto.clock,
        -makoto.verificationTimeOffset
    ),
): AttestationVerifier = AttestationVerifier(
    makoto = makoto,
    nonceGenerator = suspend { nonce },
    challengeValidator = challengeValidator,
)

private fun loadResourceText(name: String): String =
    requireNotNull(Thread.currentThread().contextClassLoader.getResourceAsStream(name)) {
        "Missing test resource: $name"
    }.bufferedReader().use { it.readText() }

private fun generateEcKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

private fun generateRsaKeyPair(keySizeBits: Int): KeyPair =
    KeyPairGenerator.getInstance("RSA").apply {
        initialize(RSAKeyGenParameterSpec(keySizeBits, RSAKeyGenParameterSpec.F4))
    }.generateKeyPair()

private fun keyPairForAttestation(attestationJson: String): KeyPair {
    val attestation = Attestation.fromJSON(attestationJson)
    val publicKey = when (attestation) {
        is AndroidKeystoreAttestation ->
            attestation.certificateChain.first().decodedPublicKey.getOrThrow()
        is IosHomebrewAttestation ->
            attestation.parsedClientData.publicKey
        else -> error("Unsupported attestation type: ${attestation::class.simpleName}")
    }
    return when (publicKey) {
        is CryptoPublicKey.EC -> generateEcKeyPair()
        is CryptoPublicKey.RSA -> generateRsaKeyPair(publicKey.bits.number.toInt())
    }
}

private fun createCsr(
    challenge: AttestationChallenge,
    attestationJson: String,
    keyPair: KeyPair,
): Pkcs10CertificationRequest {
    return createCsrWithAttributes(
        challenge,
        keyPair,
        listOf(
            Pkcs10CertificationRequestAttribute(
                challenge.proofOID,
                Asn1String.UTF8(attestationJson).encodeToTlv()
            )
        )
    )
}

private fun createCsrWithAttributes(
    challenge: AttestationChallenge,
    keyPair: KeyPair,
    attributes: List<Pkcs10CertificationRequestAttribute>,
): Pkcs10CertificationRequest {
    return createCsrWithSubject(
        subjectName = listOf(RelativeDistinguishedName(challenge.getRdnSerialNumber())),
        keyPair = keyPair,
        attributes = attributes,
    )
}

private fun createCsrWithoutNonce(
    keyPair: KeyPair,
    attestationJson: String,
): Pkcs10CertificationRequest = createCsrWithSubject(
    subjectName = emptyList(),
    keyPair = keyPair,
    attributes = listOf(
        Pkcs10CertificationRequestAttribute(
            WardenDefaults.OIDs.ATTESTATION_PROOF,
            Asn1String.UTF8(attestationJson).encodeToTlv()
        )
    ),
)

private fun createCsrWithSubject(
    subjectName: List<RelativeDistinguishedName>,
    keyPair: KeyPair,
    attributes: List<Pkcs10CertificationRequestAttribute>,
): Pkcs10CertificationRequest {
    val tbsCsr = TbsCertificationRequest(
        subjectName = subjectName,
        publicKey = keyPair.public.toCryptoPublicKey().getOrThrow(),
        attributes = attributes,
    )
    val (sigAlg, signature) = when (keyPair.private) {
        is ECPrivateKey -> X509SignatureAlgorithm.ES256 to "SHA256withECDSA"
        is RSAPrivateKey -> X509SignatureAlgorithm.RS256 to "SHA256withRSA"
        else -> error("Unsupported key algorithm: ${keyPair.private.algorithm}")
    }.let { (alg, jcaAlg) ->
        val signatureBytes = Signature.getInstance(jcaAlg).apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToDer())
        }.sign()
        alg to signatureBytes
    }
    val cryptoSignature = when (sigAlg) {
        X509SignatureAlgorithm.ES256 -> CryptoSignature.EC.decodeFromDer(signature)
        X509SignatureAlgorithm.RS256 -> CryptoSignature.RSA(signature)
        else -> error("Unsupported signature algorithm: $sigAlg")
    }
    return Pkcs10CertificationRequest(tbsCsr, sigAlg, cryptoSignature)
}

private data class FakeAndroidAttestation(
    val certificateChain: List<JcaX509Certificate>,
    val leafKeyPair: KeyPair,
    val rootCertificate: JcaX509Certificate,
)

private fun FakeAndroidAttestation.attestationJson(): String =
    AndroidKeystoreAttestation(certificateChain.toSignumChain()).jsonEncoded

private fun List<JcaX509Certificate>.toSignumChain(): List<SignumX509Certificate> =
    map { SignumX509Certificate.decodeFromDer(it.encoded) }

private fun createFakeAndroidAttestation(
    challenge: ByteArray,
    packageName: String,
    signatureDigest: ByteArray,
    creationTime: Date = Date(fixedClock.now().toEpochMilliseconds()),
    deviceLocked: Boolean = true,
    verifiedBootState: BootState = BootState.VERIFIED,
): FakeAndroidAttestation {
    val keyAttestation = KeyAttestationDefs(
        attestationVersion = 4,
        attestationSecurityLevel = SecurityLevel.TEE,
        keymasterVersion = 4,
        keymasterSecurityLevel = SecurityLevel.TEE,
        attestationChallenge = challenge,
        uniqueId = byteArrayOf(),
        softwareEnforced = SecurityProperties(
            creationDateTime = Instant.ofEpochMilli(creationTime.time),
            applicationInfo = KeyAttestationApplicationInfo(
                packageName = packageName,
                version = 1,
                signatureDigests = listOf(signatureDigest)
            )
        ),
        teeEnforced = SecurityProperties(
            keySize = 256,
            rootOfTrust = RootOfTrust(
                verifiedBootKey = Random.nextBytes(32),
                deviceLocked = deviceLocked,
                verifiedBootState = verifiedBootState,
                verifiedBootHash = Random.nextBytes(32),
            ),
            androidVersion = 11,
            androidPatchLevel = 202108,
        )
    )
    val rootKeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
    val rootCert = X509v3CertificateBuilder(
        X500Name("CN=Root"),
        BigInteger.valueOf(Random.nextLong()),
        creationTime,
        Date(creationTime.time + 1000L * 60L * 60L),
        X500Name("CN=Root"),
        rootKeyPair.subjectPublicKeyInfo()
    ).build(rootKeyPair.contentSigner()).toX509Certificate()

    val intermediateKeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
    val intermediateCert = X509v3CertificateBuilder(
        X500Name("CN=Root"),
        BigInteger.valueOf(Random.nextLong()),
        creationTime,
        Date(creationTime.time + 1000L * 60L * 60L),
        X500Name("CN=Intermediate"),
        intermediateKeyPair.subjectPublicKeyInfo()
    ).build(rootKeyPair.contentSigner()).toX509Certificate()

    val leafKeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
    val leafCert = X509v3CertificateBuilder(
        X500Name("CN=Intermediate"),
        BigInteger.valueOf(Random.nextLong()),
        creationTime,
        Date(creationTime.time + 1000L * 60L * 60L),
        X500Name("CN=Subject"),
        leafKeyPair.subjectPublicKeyInfo()
    ).addExtension(
        ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
        false,
        keyAttestation.toSequence()
    ).build(intermediateKeyPair.contentSigner()).toX509Certificate()

    return FakeAndroidAttestation(listOf(leafCert, intermediateCert, rootCert), leafKeyPair, rootCert)
}

private fun X509CertificateHolder.toX509Certificate(): JcaX509Certificate =
    java.security.cert.CertificateFactory.getInstance("X.509")
        .generateCertificate(encoded.inputStream()) as JcaX509Certificate

private fun KeyPair.contentSigner(): ContentSigner =
    JcaContentSignerBuilder("SHA256withECDSA").build(private)

private fun KeyPair.subjectPublicKeyInfo(): SubjectPublicKeyInfo =
    SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(public.encoded))

private data class KeyAttestationDefs(
    val attestationVersion: Long,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Long,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val uniqueId: ByteArray,
    val softwareEnforced: SecurityProperties,
    val teeEnforced: SecurityProperties,
) {
    fun toSequence(): DERSequence = DERSequence(
        arrayOf(
            ASN1Integer(attestationVersion),
            ASN1Enumerated(attestationSecurityLevel.value),
            ASN1Integer(keymasterVersion),
            ASN1Enumerated(keymasterSecurityLevel.value),
            DEROctetString(attestationChallenge),
            DEROctetString(uniqueId),
            softwareEnforced.toSequence(),
            teeEnforced.toSequence()
        )
    )
}

private data class SecurityProperties(
    val creationDateTime: Instant? = null,
    val keySize: Int? = null,
    val applicationInfo: KeyAttestationApplicationInfo? = null,
    val androidVersion: Int? = null,
    val androidPatchLevel: Int? = null,
    val rootOfTrust: RootOfTrust? = null,
) {
    fun toSequence(): DERSequence =
        DERSequence(
            arrayOf(
                creationDateTime?.let { DERTaggedObject(701, ASN1Integer(it.toEpochMilli())) },
                keySize?.let { DERTaggedObject(3, ASN1Integer(it.toLong())) },
                rootOfTrust?.let { DERTaggedObject(704, it.encoded()) },
                androidVersion?.let { DERTaggedObject(705, ASN1Integer(it.toLong())) },
                androidPatchLevel?.let { DERTaggedObject(706, ASN1Integer(it.toLong())) },
                applicationInfo?.let { DERTaggedObject(709, DEROctetString(it.encoded())) },
            ).filterNotNull().toTypedArray()
        )
}

private data class KeyAttestationApplicationInfo(
    val packageName: String,
    val version: Int,
    val signatureDigests: Collection<ByteArray>
) {
    fun encoded(): ByteArray = DERSequence(
        arrayOf(
            DERSet(
                DERSequence(
                    arrayOf(
                        DEROctetString(packageName.encodeToByteArray()),
                        ASN1Integer(version.toLong())
                    )
                )
            ),
            DERSet(
                signatureDigests.map { DEROctetString(it) }.toTypedArray()
            )
        )
    ).encoded
}

private data class RootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: BootState,
    val verifiedBootHash: ByteArray
) {
    fun encoded(): DERSequence = DERSequence(
        arrayOf(
            DEROctetString(verifiedBootKey),
            ASN1Boolean.getInstance(deviceLocked),
            ASN1Enumerated(verifiedBootState.value),
            DEROctetString(verifiedBootHash)
        )
    )
}

private enum class SecurityLevel(val value: Int) {
    NULL(-1),
    SOFTWARE(0),
    TEE(1),
    STRONGBOX(2);
}

private enum class BootState(val value: Int) {
    NULL(-1),
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);
}

private fun androidConfigForFake(
    packageName: String,
    signatureDigest: ByteArray,
    trustedRoots: Set<TrustedRoot>? = null,
    attestationStatementValiditySeconds: Long? = 300,
    enforceLeafValidity: Boolean = false,
    allowBootloaderUnlock: Boolean = false,
): AndroidAttestationConfiguration {
    val appData = AndroidAttestationConfiguration.AppData.Builder(packageName, signatureDigest).build()
    val builder = AndroidAttestationConfiguration.Builder(appData)
        .attestationStatementValiditySeconds(attestationStatementValiditySeconds)
    if (enforceLeafValidity) builder.enforceLeafValidity()
    if (allowBootloaderUnlock) builder.allowBootloaderUnlock()
    trustedRoots?.let { builder.hardwareTrustedRoots(it) }
    return builder.build()
}

val AttestationVerifierE2ETest by testSuite {
    "issueChallenge encodes inverse offset" {
        val nonce = Random.Default.nextBytes(16)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        challenge.issuedAt shouldBe (fixedClock.now() - verificationOffset)
    }

    "issueChallenge stores nonce once (property)" {
        val random = Random(1337)
        repeat(25) {
            val nonce = random.nextBytes(random.nextInt(1, 129))
            val verifier = verifierForNonce(nonce)
            val challenge = verifier.issueChallenge("https://example.invalid/attest")
            challenge.nonce.contentEquals(nonce) shouldBe true
            verifier.challengeValidator.validate(nonce)
                .shouldBeInstanceOf<ChallengeValidationResult.Success>()
            verifier.challengeValidator.validate(nonce)
                .shouldBeInstanceOf<ChallengeValidationResult.Failure>()
        }
    }

    e2eCases.forEach { case ->
        "e2e rejects invalid CSR signature (${case.name})" {
            val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
            val verifier = verifierForNonce(nonce)
            val challenge = verifier.issueChallenge("https://example.invalid/attest")
            val attestationJson = loadResourceText(case.attestationResource)
            val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))

            val response = verifier.verifyAttestation(
                csr,
                onPreAttestationError = { throwable.toString() },
                certificateIssuer = { emptyList() }
            )
            response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                withClue(failure.explanation ?: "no explanation") {
                    failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
                }
            }
        }
    }

    e2eCases.forEach { case ->
        "e2e rejects unknown nonce (${case.name})" {
            val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
            val verifier = verifierForNonce(nonce)
            val issued = verifier.issueChallenge("https://example.invalid/attest")

            val wrongNonce = Random.nextBytes(nonce.size).let { candidate ->
                if (candidate.contentEquals(nonce)) candidate.copyOf().also { it[0] = (it[0] + 1).toByte() } else candidate
            }

            val csrChallenge = AttestationChallenge(
                issuedAt = issued.issuedAt,
                validity = issued.validity,
                timeZone = issued.timeZone,
                nonce = wrongNonce,
                attestationEndpoint = issued.attestationEndpoint,
                proofOID = issued.proofOID,
                genericDeviceNameOID = issued.genericDeviceNameOID,
                keyConstraints = issued.keyConstraints,
            )
            val attestationJson = loadResourceText(case.attestationResource)
            val csr = createCsr(csrChallenge, attestationJson, keyPairForAttestation(attestationJson))

            val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
            response.shouldBeInstanceOf<AttestationResponse.Failure>()
            response.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "concurrent verification only consumes a challenge once" {
        val case = e2eCases.first()
        val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val attestationJson = loadResourceText(case.attestationResource)
        val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))

        val issuerCalls = AtomicInteger(0)
        val results = (1..20).map {
            async {
                verifier.verifyAttestation(
                    csr,
                    certificateIssuer = {
                        issuerCalls.incrementAndGet()
                        emptyList()
                    },
                )
            }
        }.awaitAll()

        val nonContent = results.filterNot { it is AttestationResponse.Failure && it.kind == AttestationResponse.Failure.Type.CONTENT }
        withClue("expected only one non-CONTENT result") {
            nonContent shouldHaveSize 1
        }
        withClue("issuer should run at most once") {
            (issuerCalls.get() <= 1) shouldBe true
        }
    }

    "android fake attestation verifies with custom trusted root" {
        val nonce = Random(1).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Success>()
    }

    "android fake attestation fails without trusted root" {
        val nonce = Random(2).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
        }
    }

    "android fake attestation fails on package mismatch" {
        val nonce = Random(3).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = "com.example.other",
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "android fake attestation fails on signer mismatch" {
        val nonce = Random(4).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val wrongSigner = MessageDigest.getInstance("SHA-256").digest("wrong-signer".encodeToByteArray())
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = wrongSigner,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "android fake attestation fails on challenge mismatch" {
        val nonce = Random(5).nextBytes(16)
        val otherNonce = Random(6).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = otherNonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "csr missing attestation proof fails" {
        val nonce = Random(7).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsrWithAttributes(challenge, fake.leafKeyPair, attributes = emptyList())

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "csr with invalid attestation json fails" {
        val nonce = Random(8).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, "{not-json", fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }
}

val AttestationVerifierErrorMappingTest by testSuite {
    "maps missing nonce to CONTENT (challenge extraction)" {
        val nonce = Random(100).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsrWithoutNonce(fake.leafKeyPair, fake.attestationJson())

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps unknown nonce to CONTENT (challenge validation)" {
        val nonce = Random(101).nextBytes(16)
        val wrongNonce = Random(102).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = wrongNonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val issued = verifier.issueChallenge("https://example.invalid/attest")
        val csrChallenge = AttestationChallenge(
            issuedAt = issued.issuedAt,
            validity = issued.validity,
            timeZone = issued.timeZone,
            nonce = wrongNonce,
            attestationEndpoint = issued.attestationEndpoint,
            proofOID = issued.proofOID,
            genericDeviceNameOID = issued.genericDeviceNameOID,
            keyConstraints = issued.keyConstraints,
        )
        val csr = createCsr(csrChallenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps missing attestation proof to CONTENT (attestation statement extraction)" {
        val nonce = Random(103).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsrWithAttributes(challenge, fake.leafKeyPair, attributes = emptyList())

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps untrusted root to TRUST" {
        val nonce = Random(104).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
        }
    }

    "maps certificate time errors to TIME" {
        val nonce = Random(105).nextBytes(16)
        val creationTime = Date(fixedClock.now().toEpochMilliseconds() - 48.hours.inWholeMilliseconds)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            creationTime = creationTime,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
            attestationStatementValiditySeconds = null,
            enforceLeafValidity = true,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TIME
        }
    }

    "maps statement time errors to TIME" {
        val nonce = Random(106).nextBytes(16)
        val creationTime = Date(fixedClock.now().toEpochMilliseconds() - 30.minutes.inWholeMilliseconds)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            creationTime = creationTime,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
            attestationStatementValiditySeconds = 1,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TIME
        }
    }

    "maps package mismatch to CONTENT" {
        val nonce = Random(107).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = "com.example.other",
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps signer mismatch to CONTENT" {
        val nonce = Random(108).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val wrongSigner = MessageDigest.getInstance("SHA-256").digest("wrong-signer".encodeToByteArray())
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = wrongSigner,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps bootloader state violations to CONTENT" {
        val nonce = Random(109).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            deviceLocked = false,
            verifiedBootState = BootState.UNVERIFIED,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps attestation challenge mismatch to CONTENT" {
        val nonce = Random(110).nextBytes(16)
        val otherNonce = Random(111).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = otherNonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps unsupported platform to CONTENT" {
        val nonce = Random(112).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val verifier = verifierForNonce(
            Makoto(iosConfig, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps operational errors to INTERNAL" {
        val nonce = Random(113).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(
            csr,
            certificateIssuer = { error("boom") }
        )
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.INTERNAL
        }
    }
}
