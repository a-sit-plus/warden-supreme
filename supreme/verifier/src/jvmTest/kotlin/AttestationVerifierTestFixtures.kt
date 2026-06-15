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
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
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

internal data class E2eCase(
    val name: String,
    val attestationResource: String,
    val nonceHex: String,
)

internal val e2eCases = listOf(
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

internal val fixedClock = FixedTimeClock(2024u, 10u, 1u)
internal val verificationOffset = 12.hours + 45.minutes
internal val fakeAndroidPackage = "com.example.fake.android"
internal val fakeAndroidSignerDigest = MessageDigest.getInstance("SHA-256")
    .digest("fake-signer".encodeToByteArray())
internal const val attestationEndpoint = "https://example.invalid/attest"

internal val androidConfig = AndroidAttestationConfiguration.Builder(
    AndroidAttestationConfiguration.AppData(
        packageName = "at.asitplus.cryptotest.androidApp",
        signerFingerprints = setOf(
            "941A4513A3027563D3A6EA48EEE85BA45EB9F69CEEA19EF0EBB17F100BFC8878"
                .hexToByteArray(HexFormat.UpperCase)
        ),
    )
)
    .enforceLeafValidity()
    .attestationStatementValiditySeconds(300)
    .build()

internal val iosConfig = IosAttestationConfiguration(
    IosAttestationConfiguration.AppData(
        teamIdentifier = "9CYHJNG644",
        bundleIdentifier = "at.asitplus.signumtest.iosApp",
        sandbox = true,
    )
)

internal val makoto = Makoto(
    androidAttestationConfiguration = androidConfig,
    iosAttestationConfiguration = iosConfig,
    clock = fixedClock,
    verificationTimeOffset = verificationOffset,
)

internal fun verifierForNonce(nonce: ByteArray, challengeValidator: ChallengeValidator = InMemoryChallengeCache(
    fixedClock,
    -verificationOffset
)): AttestationVerifier = AttestationVerifier(
    makoto = makoto,
    nonceGenerator = suspend { nonce },
    challengeValidator = challengeValidator,
)

internal fun verifierForNonce(
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

internal fun fixedMakoto(androidConfig: AndroidAttestationConfiguration): Makoto =
    Makoto(androidConfig, clock = fixedClock, verificationTimeOffset = 0.seconds)

internal fun loadResourceText(name: String): String =
    requireNotNull(Thread.currentThread().contextClassLoader.getResourceAsStream(name)) {
        "Missing test resource: $name"
    }.bufferedReader().use { it.readText() }

internal fun generateEcKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

internal fun generateRsaKeyPair(keySizeBits: Int): KeyPair =
    KeyPairGenerator.getInstance("RSA").apply {
        initialize(RSAKeyGenParameterSpec(keySizeBits, RSAKeyGenParameterSpec.F4))
    }.generateKeyPair()

internal fun keyPairForAttestation(attestationJson: String): KeyPair {
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

internal fun createCsr(
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

internal fun createCsrWithAttributes(
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

internal fun createCsrWithoutNonce(
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

internal fun createCsrWithSubject(
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

internal data class FakeAndroidAttestation(
    val certificateChain: List<JcaX509Certificate>,
    val leafKeyPair: KeyPair,
    val rootCertificate: JcaX509Certificate,
    val rootKeyPair: KeyPair,
    val intermediateCertificate: JcaX509Certificate,
    val intermediateKeyPair: KeyPair,
)

internal fun FakeAndroidAttestation.attestationJson(): String =
    AndroidKeystoreAttestation(certificateChain.toSignumChain()).jsonEncoded

internal fun FakeAndroidAttestation.prependForgedLeaf(
    creationTime: Date = Date(fixedClock.now().toEpochMilliseconds()),
    copyAttestationExtension: Boolean = false,
): FakeAndroidAttestation {
    val forgedLeafKeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
    val attestationLeaf = certificateChain.first()
    val builder = X509v3CertificateBuilder(
        X500Name(attestationLeaf.subjectX500Principal.name),
        BigInteger.valueOf(Random.nextLong()),
        creationTime,
        Date(creationTime.time + 1000L * 60L * 60L),
        X500Name("CN=Forged Subject"),
        forgedLeafKeyPair.subjectPublicKeyInfo()
    )
    if (copyAttestationExtension) {
        builder.addExtension(
            ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
            false,
            ASN1OctetString.getInstance(
                attestationLeaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
            ).octets
        )
    }
    val forgedLeaf = builder.build(leafKeyPair.contentSigner()).toX509Certificate()

    return copy(
        certificateChain = listOf(forgedLeaf) + certificateChain,
        leafKeyPair = forgedLeafKeyPair,
    )
}

internal fun List<JcaX509Certificate>.toSignumChain(): List<SignumX509Certificate> =
    map { SignumX509Certificate.decodeFromDer(it.encoded) }

internal data class AndroidFixture(
    val nonce: ByteArray,
    val fake: FakeAndroidAttestation,
) {
    fun verifier(config: AndroidAttestationConfiguration): AttestationVerifier =
        verifierForNonce(fixedMakoto(config), nonce)

    suspend fun issueCsr(
        verifier: AttestationVerifier,
        attestationJson: String = fake.attestationJson(),
        keyPair: KeyPair = fake.leafKeyPair,
    ): Pkcs10CertificationRequest {
        val challenge = verifier.issueChallenge(attestationEndpoint)
        return createCsr(challenge, attestationJson, keyPair)
    }

    suspend fun issueCsrWithoutAttestationProof(verifier: AttestationVerifier): Pkcs10CertificationRequest {
        val challenge = verifier.issueChallenge(attestationEndpoint)
        return createCsrWithAttributes(challenge, fake.leafKeyPair, attributes = emptyList())
    }

    fun trustedConfig(
        packageName: String = fakeAndroidPackage,
        signatureDigest: ByteArray = fakeAndroidSignerDigest,
        attestationStatementValiditySeconds: Long? = 300,
        enforceLeafValidity: Boolean = false,
        allowBootloaderUnlock: Boolean = false,
    ): AndroidAttestationConfiguration = androidConfigForFake(
        packageName = packageName,
        signatureDigest = signatureDigest,
        trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        enforceLeafValidity = enforceLeafValidity,
        allowBootloaderUnlock = allowBootloaderUnlock,
    )
}

private val fixtureSeed = AtomicInteger(900)

internal fun generateAndroidFixture(): AndroidFixture {
    val seed = fixtureSeed.incrementAndGet()
    val nonce = Random(seed).nextBytes(16)
    val fake = createFakeAndroidAttestation(
        challenge = nonce,
        packageName = fakeAndroidPackage,
        signatureDigest = fakeAndroidSignerDigest,
    )
    return AndroidFixture(nonce, fake)
}

internal fun createFakeAndroidAttestation(
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

    return FakeAndroidAttestation(
        listOf(leafCert, intermediateCert, rootCert),
        leafKeyPair,
        rootCert,
        rootKeyPair,
        intermediateCert,
        intermediateKeyPair,
    )
}

internal fun createFakeAndroidAttestationWithRoots(
    challenge: ByteArray,
    packageName: String,
    signatureDigest: ByteArray,
    creationTime: Date,
    deviceLocked: Boolean,
    verifiedBootState: BootState,
    rootKeyPair: KeyPair,
    rootCertificate: JcaX509Certificate,
    intermediateKeyPair: KeyPair,
    intermediateCertificate: JcaX509Certificate,
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

    return FakeAndroidAttestation(
        listOf(leafCert, intermediateCertificate, rootCertificate),
        leafKeyPair,
        rootCertificate,
        rootKeyPair,
        intermediateCertificate,
        intermediateKeyPair,
    )
}

internal fun X509CertificateHolder.toX509Certificate(): JcaX509Certificate =
    java.security.cert.CertificateFactory.getInstance("X.509")
        .generateCertificate(encoded.inputStream()) as JcaX509Certificate

internal fun KeyPair.contentSigner(): ContentSigner =
    JcaContentSignerBuilder("SHA256withECDSA").build(private)

internal fun KeyPair.subjectPublicKeyInfo(): SubjectPublicKeyInfo =
    SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(public.encoded))

internal data class KeyAttestationDefs(
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

internal data class SecurityProperties(
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

internal data class KeyAttestationApplicationInfo(
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

internal data class RootOfTrust(
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

internal enum class SecurityLevel(val value: Int) {
    NULL(-1),
    SOFTWARE(0),
    TEE(1),
    STRONGBOX(2);
}

internal enum class BootState(val value: Int) {
    NULL(-1),
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);
}

internal fun androidConfigForFake(
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
