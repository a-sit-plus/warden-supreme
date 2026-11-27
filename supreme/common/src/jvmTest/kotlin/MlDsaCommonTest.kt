import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.attestation.supreme.mldsa.MlDsaJcaPrivateKey
import at.asitplus.attestation.supreme.mldsa.MlDsaKeyConfiguration
import at.asitplus.attestation.supreme.mldsa.MlDsaParameterSet
import at.asitplus.attestation.supreme.mldsa.MlDsaPublicKey
import at.asitplus.attestation.supreme.mldsa.MlDsaSignature
import at.asitplus.attestation.supreme.mldsa.MlDsaSignatureAlgorithm
import at.asitplus.attestation.supreme.mldsa.installWardenMlDsa
import at.asitplus.attestation.supreme.mldsa.mlDsa
import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.sign.signerFor
import at.asitplus.signum.indispensable.sign.verifierFor
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.toPublicKey
import at.asitplus.signum.supreme.os.JKSSigningKeyConfiguration
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.json.Json
import net.mamoe.yamlkt.Yaml
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant
import java.security.PublicKey as JcaPublicKey
import java.security.Signature as JcaSignature

private val bc = BouncyCastleProvider()

private fun bcKeyPair(set: MlDsaParameterSet) = KeyPairGenerator.getInstance(set.jcaName, bc).generateKeyPair()

val MlDsaCommonTest by matrixSuite {
    Signum.installWardenMlDsa()
    val message = "warden ml-dsa".encodeToByteArray()

    data("SPKI round-trips against BouncyCastle", MlDsaParameterSet.entries, nameFn = { _, it -> it.jcaName }) test { set ->
        val pair = bcKeyPair(set)
        val decoded = PublicKey.fromAsn1(pair.public.encoded).shouldBeInstanceOf<MlDsaPublicKey>()
        decoded.parameterSet shouldBe set
        decoded.rawBytes.size shouldBe set.publicKeySize
        decoded.asn1.toDer().contentEquals(pair.public.encoded) shouldBe true
        // value semantics, as required by iOS ClientData and Makoto
        PublicKey.fromAsn1(pair.public.encoded) shouldBe decoded
        decoded.hashCode() shouldBe PublicKey.fromAsn1(pair.public.encoded).hashCode()
        decoded shouldNotBe PublicKey.fromAsn1(bcKeyPair(set).public.encoded)
        // JCA mapping in both directions
        pair.public.toPublicKey() shouldBe decoded
        decoded.toJcaPublicKey().encoded.contentEquals(pair.public.encoded) shouldBe true
    }

    data("JDK 17 style SPKI with NULL parameters", MlDsaParameterSet.entries, nameFn = { _, it -> it.jcaName }) test { set ->
        val pair = bcKeyPair(set)
        val spki = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        val withNull = SubjectPublicKeyInfo(AlgorithmIdentifier(spki.algorithm.algorithm, DERNull.INSTANCE), spki.publicKeyData.octets).encoded
        // strict ASN.1 decoding rejects it (RFC 9881) ...
        shouldThrowAny { (PublicKey.fromAsn1(withNull) as MlDsaPublicKey) }
        // ... but a JCA key that encodes itself that way (sun.security.x509.X509Key on JDK 17) still maps
        val jdkStyle = object : JcaPublicKey {
            override fun getAlgorithm() = spki.algorithm.algorithm.id
            override fun getFormat() = "X.509"
            override fun getEncoded() = withNull
        }
        jdkStyle.toPublicKey() shouldBe pair.public.toPublicKey()
    }

    data("sign and verify", MlDsaParameterSet.entries, nameFn = { _, it -> it.jcaName }) test { set ->
        val key = MlDsaJcaPrivateKey.generate(set)
        val algorithm = MlDsaSignatureAlgorithm[set]
        val signature = algorithm.signerFor(key).sign(message).signature.shouldBeInstanceOf<MlDsaSignature>()
        signature.rawBytes.size shouldBe set.signatureSize
        algorithm.verifierFor(key.publicKey).verify(message, signature) shouldBe SignatureVerifier.Success
        // BC agrees
        JcaSignature.getInstance(set.jcaName, bc).run {
            initVerify(key.publicKey.toJcaPublicKey()); update(message); verify(signature.rawBytes)
        } shouldBe true
        // tampering is detected
        val tampered = MlDsaSignature(signature.rawBytes.also { it[17] = (it[17].toInt() xor 1).toByte() })
        shouldThrowAny { algorithm.verifierFor(key.publicKey).verify(message, tampered) }
        // parameter set mismatch is rejected
        val other = MlDsaParameterSet.entries.first { it != set }
        shouldThrowAny { MlDsaSignatureAlgorithm[other].verifierFor(key.publicKey) }
    }

    data("algorithm identifier", MlDsaParameterSet.entries, nameFn = { _, it -> it.jcaName }) test { set ->
        val algorithm = MlDsaSignatureAlgorithm[set]
        val der = algorithm.asn1.toDer()
        // SEQUENCE { OID } without parameters (RFC 9881)
        der.contentEquals(AlgorithmIdentifier(org.bouncycastle.asn1.ASN1ObjectIdentifier(set.oid.toString())).encoded) shouldBe true
        SignatureAlgorithm.fromAsn1(der) shouldBeSameInstanceAs algorithm
    }

    data("self-signed certificate parses in JDK and verifies with BC", MlDsaParameterSet.entries, nameFn = { _, it -> it.jcaName }) test { set ->
        val key = MlDsaJcaPrivateKey.generate(set)
        val signer = MlDsaSignatureAlgorithm[set].signerFor(key)
        val name = Name.fromString("CN=Warden ML-DSA")
        val start = Instant.parse("2026-01-01T00:00:00Z")
        val certificate = signer.sign(
            TbsCertificate(
                serialNumber = BigInteger.ONE,
                validFrom = start,
                validUntil = start + 1.hours,
                signatureAlgorithm = signer.signatureAlgorithm,
                publicKey = signer.publicKey,
                issuerName = name,
                subjectName = name,
            )
        )
        val der = certificate.asn1.toDer()
        val reparsed = Certificate.fromAsn1(der)
        reparsed.publicKey shouldBe key.publicKey
        reparsed.signatureAlgorithm shouldBeSameInstanceAs MlDsaSignatureAlgorithm[set]
        reparsed.signature.shouldBeInstanceOf<MlDsaSignature>()

        val jdk = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
        jdk.verify(key.publicKey.toJcaPublicKey(), bc)
        jdk.sigAlgOID shouldBe set.oid.toString()
    }

    test("DSL option selects ML-DSA and deselects EC and RSA") {
        val defaultConfig = DSL.resolve(::JKSSigningKeyConfiguration, null)
        defaultConfig.ec.v shouldNotBe null
        defaultConfig.mlDsa.v shouldBe null

        val config = DSL.resolve(::JKSSigningKeyConfiguration) { mlDsa { parameterSet = MlDsaParameterSet.ML_DSA_87 } }
        config.ec.v shouldBe null
        config.rsa.v shouldBe null
        config.mlDsa.v.shouldBeInstanceOf<MlDsaKeyConfiguration>().parameterSet shouldBe MlDsaParameterSet.ML_DSA_87
        DSL.resolve(::JKSSigningKeyConfiguration) { mlDsa { } }.mlDsa.v!!.parameterSet shouldBe MlDsaParameterSet.ML_DSA_65
    }

    test("built-in keys still decode") {
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        PublicKey.fromAsn1(ec.public.encoded).shouldBeInstanceOf<EcdsaPublicKey>().curve shouldBe ECCurve.SECP_256_R_1
        ec.public.toPublicKey().shouldBeInstanceOf<EcdsaPublicKey>()
    }

    data(
        "KeyConstraints round-trip",
        listOf(
            KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA()),
            KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA(MlDsaParameterSet.ML_DSA_87)),
            WardenDefaults.KeyConstraints.mlDsa65Signer,
            WardenDefaults.KeyConstraints.p256Signer,
            KeyConstraints(KeyConstraints.AlgorithmParameters.RSA(BitLength(2048u))),
            KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA(), KeyConstraints.KeyProtection(deviceLock = true)),
        ),
        nameFn = { i, it -> "$i ${it.algorithmParameters::class.simpleName}" },
    ) test { constraints ->
        val json = Json.encodeToString(KeyConstraints.serializer(), constraints)
        Json.decodeFromString(KeyConstraints.serializer(), json) shouldBe constraints
        val yaml = Yaml.encodeToString(KeyConstraints.serializer(), constraints)
        Yaml.decodeFromString(KeyConstraints.serializer(), yaml) shouldBe constraints
    }

    test("KeyConstraints ML-DSA wire format") {
        val json = Json.encodeToString(KeyConstraints.serializer(), WardenDefaults.KeyConstraints.mlDsa65Signer)
        // defaults are not encoded, as for EC's curve
        json shouldBe """{"algorithmParameters":{"type":"ML-DSA"}}"""
        Json.encodeToString(
            KeyConstraints.serializer(),
            KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA(MlDsaParameterSet.ML_DSA_87))
        ) shouldBe """{"algorithmParameters":{"type":"ML-DSA","parameterSet":"ML-DSA-87"}}"""
        WardenDefaults.KeyConstraints.mlDsa65Signer.algorithmParameters.digests shouldBe emptySet()
        WardenDefaults.KeyConstraints.mlDsa65Signer shouldNotBe
                KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA(MlDsaParameterSet.ML_DSA_87))
    }
}
