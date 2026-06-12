package at.asitplus.attestation.android

import at.asitplus.attestation.android.engine.CertChainValidator
import at.asitplus.signum.indispensable.toKmpCertificate
import kotlin.time.toKotlinInstant
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel as AttestationSecurityLevel
import at.asitplus.attestation.android.engine.JvmCertChainValidator
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.data.FakeAttestations
import at.asitplus.attestation.data.SecurityLevel
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.reflect.KClass
import kotlin.time.Instant

private val contractInstant = Instant.parse("2025-01-10T00:00:00Z")
private val contractDate = Date(contractInstant.toEpochMilliseconds() + 30 * 60_000)
private val attestationOid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

/** Same expected outcomes for both backends; replace one JVM construction below when Supreme is ready. */
val CertChainValidatorContractTest by matrixSuite {
    val factory = chainFixture(Provisioning.FACTORY)
    val rkp = chainFixture(Provisioning.RKP)
    val factoryStrongBox = chainFixture(Provisioning.FACTORY, SecurityLevel.STRONGBOX)
    val rkpStrongBox = chainFixture(Provisioning.RKP, SecurityLevel.STRONGBOX)
    val acceptedUnknownLevel = ChainOutcome()
    val trustFailure = ChainOutcome(failure = CertificateInvalidException::class, reason = "TRUST")
    val rkpFailure = ChainOutcome(failure = AttestationValueException::class, reason = "SEC_LEVEL")
    val root = factory.chain.last()
    val roots = setOf(TrustedRoot.Certificate(root))
    val renewedRoot = root.reissue(factory.rootKey, serial = root.serialNumber + BigInteger.ONE)
    val renewedChain = factory.chain.dropLast(1) + renewedRoot
    val softwareName = X500Principal("CN=Software Attestation")
    val softwareChain = listOf(
        factory.chain.first().reissue(factory.attestationKey, issuer = softwareName),
        factory.chain[1].reissue(factory.rootKey, issuer = root.subjectX500Principal, subject = softwareName),
        root,
    )

    val cases = buildList {
        // Unmodified :generator output is the baseline; signed mutations exercise the edge cases below.
        add(ChainCase("accept generated factory TEE with unknown chain security level", factory.generatedChain, acceptedUnknownLevel))
        add(ChainCase("accept generated factory StrongBox", factoryStrongBox.generatedChain,
        add(ChainCase("accept generated RKP TEE when RKP is required", rkp.generatedChain, acceptedRkp, requireRkp = true))
        add(ChainCase("accept generated RKP StrongBox", rkpStrongBox.generatedChain,
        add(ChainCase("accept three-certificate software shape with unknown chain security level", softwareChain, acceptedUnknownLevel))
        add(ChainCase("reject generated factory chain when RKP is required", factory.generatedChain, rkpFailure, requireRkp = true))

        add(ChainCase("accept unnamed public-key anchor", factory.chain, acceptedUnknownLevel,
            roots = setOf(TrustedRoot.PublicKey(root.publicKey))))
        add(ChainCase("accept matching named public-key anchor", factory.chain, acceptedUnknownLevel,
            roots = setOf(TrustedRoot.PublicKey(root.publicKey, root.subjectX500Principal))))
        add(ChainCase("reject wrong anchor name despite matching key", factory.chain, trustFailure,
            roots = setOf(TrustedRoot.PublicKey(root.publicKey, X500Principal("CN=Wrong CA")))))
        add(ChainCase("accept renewed root under public-key anchor", renewedChain, acceptedUnknownLevel,
            roots = setOf(TrustedRoot.PublicKey(root.publicKey))))
        add(ChainCase("accept renewed root when its exact certificate is trusted", renewedChain, acceptedUnknownLevel))
        add(ChainCase("reject renewed root under original certificate pin", renewedChain,
            ChainOutcome(failure = CertificateInvalidException.NoMatchingRoot::class, reason = "TRUST", certificateIndex = 3),
            roots = roots))
        add(ChainCase("reject untrusted root before checking RKP requirement", factory.chain,
            ChainOutcome(failure = CertificateInvalidException.NoMatchingRoot::class, reason = "TRUST", certificateIndex = 3),
            roots = setOf(TrustedRoot.Certificate(rkp.chain.last())), requireRkp = true))

        add(ChainCase("reject invalid leaf signature", factory.chain.replaceAt(0,
            factory.chain.first().reissue(factory.rootKey)), trustFailure.copy(certificateIndex = 0)))
        add(ChainCase("reject invalid self-signature even when root certificate is pinned",
            factory.chain.dropLast(1) + root.reissue(factory.attestationKey),
            ChainOutcome(failure = CertificateInvalidException.InvalidRoot::class, reason = "TRUST", certificateIndex = 3)))
        add(ChainCase("reject missing intermediate", factory.chain.filterIndexed { index, _ -> index != 2 },
            trustFailure.copy(certificateIndex = 1)))
        add(ChainCase("reject reordered intermediates", listOf(factory.chain[0], factory.chain[2], factory.chain[1], root),
            trustFailure.copy(certificateIndex = 2)))
        add(ChainCase("reject missing root", factory.chain.dropLast(1),
            ChainOutcome(failure = CertificateInvalidException.NoMatchingRoot::class, reason = "TRUST", certificateIndex = 2),
            roots = roots))

        val wrongName = factory.chain.replaceAt(1,
            factory.chain[1].reissue(factory.intermediateKey, issuer = X500Principal("CN=Wrong Issuer")))
        wrongName.checkPairSignatures()
        add(ChainCase("reject name chaining mismatch despite valid signatures", wrongName, trustFailure))
        add(ChainCase("reject missing attestation extension on target", factory.chain.replaceAt(0,
            factory.chain.first().reissue(factory.attestationKey,
                extensions = factory.chain.first().extensions().filterNot { it.extnId == attestationOid })), trustFailure))
        add(ChainCase("reject attestation extension on an intermediate", factory.chain.replaceAt(1,
            factory.chain[1].reissue(factory.intermediateKey,
                extensions = factory.chain[1].extensions() + factory.chain.first().extensions().single { it.extnId == attestationOid })),
            trustFailure))
        for (withExtension in listOf(false, true)) {
            val child = factory.chain.first().reissue(factory.leafKey,
                issuer = factory.chain.first().subjectX500Principal,
                subject = X500Principal("CN=Signed Child"),
                extensions = if (withExtension) factory.chain.first().extensions() else emptyList())
            val extended = listOf(child) + factory.chain
            extended.checkPairSignatures()
            add(ChainCase("reject signed child below target, attestation extension = $withExtension", extended, trustFailure))
        }

        // Characterize the Android validator's compatibility rules, rather than imposing generic PKIX rules.
        add(ChainCase("accept intermediate without basic constraints or key usage", factory.chain.replaceAt(1,
            factory.chain[1].reissue(factory.intermediateKey,
                extensions = factory.chain[1].extensions().filterNot {
                    it.extnId == Extension.basicConstraints || it.extnId == Extension.keyUsage
                })), acceptedUnknownLevel))
        add(ChainCase("accept unrecognized critical extension", factory.chain.replaceAt(0,
            factory.chain.first().reissue(factory.attestationKey,
                extensions = factory.chain.first().extensions() + Extension(
                    ASN1ObjectIdentifier("1.3.6.1.4.1.60387.999"), true, DERNull.INSTANCE.encoded))), acceptedUnknownLevel))

        for ((timeName, date) in listOf("not yet valid" to Date(contractInstant.toEpochMilliseconds() - 1_000),
            "expired" to Date(contractInstant.toEpochMilliseconds() + 2 * 60 * 60_000))) {
            for (policy in listOf(
                ValidityPolicy("global disabled", false, null, true),
                ValidityPolicy("global enabled", true, null, false),
                ValidityPolicy("root disables global", true, false, true),
                ValidityPolicy("root enables global", false, true, false),
            )) {
                add(ChainCase("factory $timeName, ${policy.name}", factory.chain,
                    if (policy.accepted) acceptedUnknownLevel else ChainOutcome(
                        failure = CertificateInvalidException.InvalidRoot::class, reason = "TIME", certificateIndex = 3),
                    roots = setOf(policy.rootPolicy?.let { TrustedRoot.Certificate(root, it) } ?: TrustedRoot.Certificate(root)),
                    enforceFactoryValidity = policy.globalPolicy, date = date))
            }
            add(ChainCase("reject RKP $timeName even with root and global validity disabled", rkp.chain,
                ChainOutcome(failure = CertificateInvalidException.InvalidRoot::class, reason = "TIME", certificateIndex = 4),
                roots = setOf(TrustedRoot.Certificate(rkp.chain.last(), false)), enforceFactoryValidity = false, date = date))
            val before = if (timeName == "expired") Date(contractDate.time - 60_000) else Date(contractDate.time + 60_000)
            val after = Date(before.time + 30_000)
            val leafInvalid = rkp.chain.replaceAt(0,
                rkp.chain.first().reissue(rkp.attestationKey, notBefore = before, notAfter = after))
            add(ChainCase("reject RKP leaf $timeName when leaf validity is enabled", leafInvalid,
                ChainOutcome(failure = CertificateInvalidException::class, reason = "TIME", certificateIndex = 0)))
            add(ChainCase("accept RKP leaf $timeName when leaf validity is ignored", leafInvalid,
                acceptedRkp, ignoreLeafValidity = true))
            val intermediateInvalid = rkp.chain.replaceAt(1,
                rkp.chain[1].reissue(rkp.intermediateKey, notBefore = before, notAfter = after))
            add(ChainCase("reject RKP intermediate $timeName even when leaf validity is ignored", intermediateInvalid,
                ChainOutcome(failure = CertificateInvalidException::class, reason = "TIME", certificateIndex = 1),
                ignoreLeafValidity = true))
        }

        for (index in listOf(0, 1, factory.chain.lastIndex)) {
            val list = AndroidRevocationList(mapOf(factory.chain[index].serialNumber.toString(16) to
                AndroidRevocationList.Entry(AndroidRevocationList.RevocationStatus.REVOKED)))
            val config = AndroidRevocationList.InMemoryLoader.Configuration(list)
            val snapshots = listOf(ConfigWithList(config, list))
            add(ChainCase(if (index == factory.chain.lastIndex) "accept root listed as revoked: anchor is excluded"
                else "reject revoked certificate at index $index", factory.chain,
                if (index == factory.chain.lastIndex) acceptedUnknownLevel.copy(revocationLists = snapshots)
                else ChainOutcome(failure = RevocationException.Revoked::class, certificateIndex = index, revocationLists = snapshots),
                revocation = listOf(config)))
        }
        val clearList = AndroidRevocationList(emptyMap())
        val clearConfig = AndroidRevocationList.InMemoryLoader.Configuration(clearList)
        add(ChainCase("accept clear revocation list and retain snapshot", factory.chain,
            acceptedUnknownLevel.copy(revocationLists = listOf(ConfigWithList(clearConfig, clearList))),
            revocation = listOf(clearConfig)))
        val unavailable = object : AndroidRevocationList.Loader.Configuration<AndroidRevocationList.Loader> {
            override val fallbackRevocationListValiditySeconds = 0L
            override fun createLoader() = object : AndroidRevocationList.Loader {
                override val fallbackRevocationListValiditySeconds = 0L
                override suspend fun load(now: Instant): AndroidRevocationList = error("Deliberately unavailable")
            }
        }
        add(ChainCase("reject unavailable revocation list", factory.chain,
            ChainOutcome(failure = RevocationException.ListUnavailable::class), revocation = listOf(unavailable)))
    }

    data("chain validation contract", cases, nameFn = { it.name }) test { case ->
        val configuration = case.configuration()
        assertChainValidatorContract(case,
            JvmCertChainValidator(configuration),
            JvmCertChainValidator(configuration),
        )
    }
}

private data class ChainOutcome(
    val failure: KClass<out Throwable>? = null,
    val reason: String? = null,
    val certificateIndex: Int? = null,
    val revocationLists: List<ConfigWithList> = emptyList(),
)

private data class ValidityPolicy(val name: String, val globalPolicy: Boolean, val rootPolicy: Boolean?, val accepted: Boolean)

private data class ChainCase(
    val name: String,
    val chain: List<X509Certificate>,
    val expected: ChainOutcome,
    val roots: Collection<TrustedRoot> = setOf(TrustedRoot.Certificate(chain.last())),
    val requireRkp: Boolean = false,
    val enforceFactoryValidity: Boolean = true,
    val ignoreLeafValidity: Boolean = false,
    val date: Date = contractDate,
    val revocation: List<AndroidRevocationList.Loader.Configuration<*>> = emptyList(),
) {
    fun configuration() = AndroidAttestationConfiguration(
        applications = listOf(AndroidAttestationConfiguration.AppData("unused", setOf(byteArrayOf(1)))),
        hardwareTrustedRoots = roots.toSet(),
        enforceFactoryProvisionedChainValidity = enforceFactoryValidity,
        ignoreLeafValidity = ignoreLeafValidity,
        revocation = revocation,
    )
}

private suspend fun assertChainValidatorContract(
    case: ChainCase,
    first: CertChainValidator,
    second: CertChainValidator,
) {
    val firstOutcome = observeChainValidator(first, case)
    val secondOutcome = observeChainValidator(second, case)
    withClue("first validator: ${first::class.simpleName}") { firstOutcome shouldBe case.expected }
    withClue("second validator: ${second::class.simpleName}") { secondOutcome shouldBe case.expected }
    withClue("validators must agree") { firstOutcome shouldBe secondOutcome }
}

private suspend fun observeChainValidator(validator: CertChainValidator, case: ChainCase): ChainOutcome {
    val result = with(validator) { case.chain.map { it.toKmpCertificate() }.verify(case.date.toInstant().toKotlinInstant(), case.roots, case.requireRkp) }
    val lists = result.revocationLists
    return when (val failure = result.verdict.exceptionOrNull()) {
        null -> ChainOutcome(securityLevel = result.verdict.getOrThrow(), revocationLists = lists)
        is CertificateInvalidException -> ChainOutcome(failure::class, failure.reason.name,
            case.chain.map { it.toKmpCertificate() }.indexOf(failure.invalidCertificate).takeIf { it >= 0 }, revocationLists = lists)
        is AttestationValueException -> ChainOutcome(failure::class, failure.reason.name, revocationLists = lists)
        is RevocationException.Revoked -> ChainOutcome(failure::class,
            certificateIndex = case.chain.map { it.toKmpCertificate() }.indexOf(failure.revokedCertificate), revocationLists = lists)
        is RevocationException.ListUnavailable -> ChainOutcome(failure::class, revocationLists = lists)
        else -> throw AssertionError("Unexpected validator failure", failure)
    }
}

private data class ChainFixture(
    val generatedChain: List<X509Certificate>,
    val chain: List<X509Certificate>,
    val rootKey: PrivateKey,
    val intermediateKey: PrivateKey,
    val attestationKey: PrivateKey,
    val leafKey: PrivateKey,
)

private fun chainFixture(provisioning: Provisioning, level: SecurityLevel = SecurityLevel.TEE): ChainFixture {
    val generated = FakeAttestations.createAttestationWithKeys(
        challenge = byteArrayOf(1, 2, 3, 4), packageName = "contract.test", signatureDigest = ByteArray(32) { 1 },
        creationTime = Date(contractInstant.toEpochMilliseconds()), securityLevel = level, provisioning = provisioning,
    )
    // Retain the attestation key so negative cases can change signed contents without breaking signatures.
    val key = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    val identifiers = JcaX509ExtensionUtils()
    val attestation = generated.certificateChain[1].reissue(generated.intermediateKeyPair.private, publicKey = key.public,
        extensions = generated.certificateChain[1].extensions().filterNot { it.extnId == Extension.subjectKeyIdentifier } +
            Extension(Extension.subjectKeyIdentifier, false, identifiers.createSubjectKeyIdentifier(key.public).encoded))
    val leaf = generated.certificateChain.first().reissue(key.private,
        extensions = generated.certificateChain.first().extensions().filterNot { it.extnId == Extension.authorityKeyIdentifier } +
            Extension(Extension.authorityKeyIdentifier, false, identifiers.createAuthorityKeyIdentifier(key.public).encoded))
    return ChainFixture(generated.certificateChain, listOf(leaf, attestation) + generated.certificateChain.drop(2),
        generated.rootKeyPair.private, generated.intermediateKeyPair.private, key.private, generated.leafKeyPair.private)
}

private fun List<X509Certificate>.replaceAt(index: Int, certificate: X509Certificate) =
    mapIndexed { i, original -> if (i == index) certificate else original }

private fun List<X509Certificate>.checkPairSignatures() = zipWithNext { certificate, parent -> certificate.verify(parent.publicKey) }

private fun X509Certificate.extensions(): List<Extension> = JcaX509CertificateHolder(this).extensions?.let { extensions ->
    extensions.extensionOIDs.map { extensions.getExtension(it) }
}.orEmpty()

private fun X509Certificate.reissue(
    key: PrivateKey,
    issuer: X500Principal = issuerX500Principal,
    subject: X500Principal = subjectX500Principal,
    publicKey: PublicKey = this.publicKey,
    serial: BigInteger = serialNumber,
    notBefore: Date = this.notBefore,
    notAfter: Date = this.notAfter,
    extensions: List<Extension> = extensions(),
): X509Certificate {
    val builder = X509v3CertificateBuilder(X500Name.getInstance(issuer.encoded), serial, notBefore, notAfter,
        X500Name.getInstance(subject.encoded), SubjectPublicKeyInfo.getInstance(publicKey.encoded))
    extensions.forEach { builder.addExtension(it) }
    val encoded = builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key)).encoded
    return CertificateFactory.getInstance("X.509").generateCertificate(encoded.inputStream()) as X509Certificate
}
