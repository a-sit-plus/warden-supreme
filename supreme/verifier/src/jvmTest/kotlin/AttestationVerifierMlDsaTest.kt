@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.canonicalPublicKey
import at.asitplus.attestation.data.FakeAttestations
import at.asitplus.attestation.supreme.mldsa.MlDsaJcaPrivateKey
import at.asitplus.attestation.supreme.mldsa.MlDsaParameterSet
import at.asitplus.attestation.supreme.mldsa.MlDsaPublicKey
import at.asitplus.attestation.supreme.mldsa.MlDsaSignature
import at.asitplus.attestation.supreme.mldsa.MlDsaSignatureAlgorithm
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.StrictJson
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.CsrAttribute
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signerFor
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.random.Random

private data class MlDsaFixture(
    val key: MlDsaJcaPrivateKey,
    val chain: List<X509Certificate>,
    val verifier: AttestationVerifier,
    val challenge: AttestationChallenge,
    val hashInput: AttestationHashInput?,
) {
    val attestationJson get() = AndroidKeystoreAttestation(chain.toSignumChain()).jsonEncoded
    val proofAttribute get() = CsrAttribute(challenge.proofOID, Asn1String.UTF8(attestationJson).encodeToTlv())
}

/**
 * A fake Android chain whose leaf is an ML-DSA key, as Android 17's Keystore produces it
 * (ML-DSA leaf, EC attestation certificates above it).
 */
private suspend fun mlDsaFixture(
    set: MlDsaParameterSet,
    dataAuth: DataAuthentication,
    key: MlDsaJcaPrivateKey = MlDsaJcaPrivateKey.generate(set),
): MlDsaFixture {
    val nonce = Random.nextBytes(16)
    // The challenge's RDN depends on the nonce only, so it can be predicted for the hash input.
    val template = AttestationChallenge(
        issuedAt = fixedClock.now(),
        validity = kotlin.time.Duration.ZERO,
        nonce = nonce,
        attestationEndpoint = attestationEndpoint,
        proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID = null,
    )
    val hashInput = (dataAuth as? DataAuthentication.Hash)?.let {
        AttestationHashInput(subjectName = listOf(RelativeDistinguishedName(template.getRdnSerialNumber())))
    }
    val attestedNonce = when (dataAuth) {
        DataAuthentication.Signature -> nonce
        is DataAuthentication.Hash -> dataAuth.algorithm.digest(hashInput!!.encodeToDer())
    }
    val chain = FakeAttestations.createAttestationForKey(
        subjectKey = key.publicKey,
        challenge = attestedNonce,
        packageName = fakeAndroidPackage,
        signatureDigest = fakeAndroidSignerDigest,
        creationTime = Date(fixedClock.now().toEpochMilliseconds()),
    )
    val verifier = AttestationVerifier(
        makoto = fixedMakoto(
            androidConfigForFake(
                packageName = fakeAndroidPackage,
                signatureDigest = fakeAndroidSignerDigest,
                trustedRoots = setOf(TrustedRoot.Certificate(chain.last())),
            )
        ),
        genericDeviceNameOID = null,
        defaultKeyConstraints = KeyConstraints(KeyConstraints.AlgorithmParameters.MLDSA(set)),
        nonceGenerator = suspend { nonce },
    )
    val challenge = verifier.issueChallenge(attestationEndpoint, dataAuth = dataAuth)
    return MlDsaFixture(key, chain, verifier, challenge, hashInput)
}

private fun MlDsaFixture.tbsCsr(publicKey: MlDsaPublicKey = key.publicKey) = TbsCertificationRequest(
    subjectName = Name(listOf(RelativeDistinguishedName(challenge.getRdnSerialNumber()))),
    publicKey = publicKey,
    attributes = listOf(proofAttribute),
)

private suspend fun MlDsaFixture.signedProof(signingKey: MlDsaJcaPrivateKey = key): CertificationRequest =
    signingKey.publicKey.signatureAlgorithm.signerFor(signingKey).sign(tbsCsr(signingKey.publicKey))

private fun MlDsaFixture.proof(): AttestationProof = when (challenge.dataAuth) {
    DataAuthentication.Signature -> error("use signedProof()")
    is DataAuthentication.Hash -> AttestationProof.Hashed(hashInput!!.toTbsCsr(key.publicKey, proofAttribute))
}

private suspend fun AttestationVerifier.verifyCapturing(proof: AttestationProof): Pair<AttestationResponse, Any?> {
    var captured: Any? = null
    val response = verifyAttestation(
        proof,
        onPreAttestationError = { captured = this; null },
        onAttestationSuccess = { captured = it },
        certificateIssuer = { emptyList() },
    )
    return response to captured
}

private val mlDsaSets = listOf(MlDsaParameterSet.ML_DSA_65, MlDsaParameterSet.ML_DSA_87)

val AttestationVerifierMlDsaTest by matrixSuite(
    // one test temporarily removes the global BouncyCastle provider
    matrixConfig { execution = ExecutionMode.Sequential }
) {

    data("challenge requests ML-DSA", mlDsaSets, nameFn = { _, it -> it.jcaName }) test { set ->
        val fixture = mlDsaFixture(set, DataAuthentication.Signature)
        fixture.challenge.keyConstraints?.algorithmParameters.shouldBeInstanceOf<KeyConstraints.AlgorithmParameters.MLDSA>()
            .parameterSet shouldBe set
        // survives the wire
        val json = Json.encodeToString(AttestationChallenge.serializer(), fixture.challenge)
        Json.decodeFromString(AttestationChallenge.serializer(), json).keyConstraints shouldBe fixture.challenge.keyConstraints
    }

    data("signed ML-DSA CSR verifies", mlDsaSets, nameFn = { _, it -> it.jcaName }) test { set ->
        val fixture = mlDsaFixture(set, DataAuthentication.Signature)
        val csr = fixture.signedProof()
        csr.signatureAlgorithm shouldBe MlDsaSignatureAlgorithm[set]
        // the CSR survives DER encoding and parsing (as when POSTed)
        val reparsed = CertificationRequest.fromAsn1(csr.asn1.toDer())
        reparsed.signature.shouldBeInstanceOf<MlDsaSignature>()

        val (response, captured) = fixture.verifier.verifyCapturing(AttestationProof.Signed(reparsed))
        response.shouldBeInstanceOf<AttestationResponse.Success>()
        captured shouldBe fixture.key.publicKey
    }

    data("hashed ML-DSA TBS CSR verifies", mlDsaSets, nameFn = { _, it -> it.jcaName }) test { set ->
        val fixture = mlDsaFixture(set, DataAuthentication.Hash(Digest.SHA256))
        val (response, captured) = fixture.verifier.verifyCapturing(fixture.proof())
        response.shouldBeInstanceOf<AttestationResponse.Success>()
        captured shouldBe fixture.key.publicKey
    }

    test("tampered ML-DSA CSR signature is rejected") {
        val fixture = mlDsaFixture(MlDsaParameterSet.ML_DSA_65, DataAuthentication.Signature)
        val csr = fixture.signedProof()
        val bytes = (csr.signature as MlDsaSignature).rawBytes.also { it[42] = (it[42].toInt() xor 0x01).toByte() }
        val tampered = CertificationRequest(csr.tbsCsr, csr.signatureAlgorithm, MlDsaSignature(bytes))
        val (response, _) = fixture.verifier.verifyCapturing(AttestationProof.Signed(tampered))
        response.shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.TRUST
    }

    data(
        "CSR for a different ML-DSA key than the attested one is rejected",
        listOf<DataAuthentication>(DataAuthentication.Signature, DataAuthentication.Hash(Digest.SHA256)),
        nameFn = { _, it -> it.toString() },
    ) test { auth ->
        val fixture = mlDsaFixture(MlDsaParameterSet.ML_DSA_65, auth)
        val other = MlDsaJcaPrivateKey.generate(MlDsaParameterSet.ML_DSA_65)
        val proof = when (auth) {
            DataAuthentication.Signature -> AttestationProof.Signed(fixture.signedProof(signingKey = other))
            is DataAuthentication.Hash -> AttestationProof.Hashed(fixture.hashInput!!.toTbsCsr(other.publicKey, fixture.proofAttribute))
        }
        val (response, captured) = fixture.verifier.verifyCapturing(proof)
        response.shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe AttestationResponse.Failure.Type.TRUST
        captured.shouldBeInstanceOf<PreAttestationError.ClientDataValidation>().reason shouldBe
                PreAttestationError.ClientDataValidation.Reason.ATTESTED_PUBLIC_KEY_MISMATCH
    }

    test("Android leaf key is canonically encoded for ML-DSA, even when the JDK re-encodes it") {
        val key = MlDsaJcaPrivateKey.generate(MlDsaParameterSet.ML_DSA_65)
        val spki = key.publicKey.asn1.toDer()
        // Other code in this JVM may have registered providers that make the JDK hand out BC keys: BouncyCastle (App Attest
        // library) and Google's KeyAttestation provider (Roboto's RTG chain validator). An Android-only deployment using
        // the Supreme chain validator has neither, so parse the leaf with JDK providers only. The chain is created inside
        // this window, because the JDK caches parsed certificates by their encoding.
        val nonJdk = Security.getProviders().withIndex().filter { it.value.name in setOf("BC", "KeyAttestation") }
        nonJdk.forEach { Security.removeProvider(it.value.name) }
        try {
            val der = FakeAttestations.createAttestationForKey(
                subjectKey = key.publicKey,
                challenge = Random.nextBytes(16),
                packageName = fakeAndroidPackage,
                signatureDigest = fakeAndroidSignerDigest,
            ).first().encoded
            val jdkLeaf = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
            // JDK 17's generic X509Key re-encodes the SPKI with NULL parameters
            if (Runtime.version().feature() < 21) jdkLeaf.publicKey.encoded.contentEquals(spki) shouldBe false
            jdkLeaf.canonicalPublicKey().encoded.contentEquals(spki) shouldBe true
        } finally {
            nonJdk.forEach { (index, provider) -> Security.insertProviderAt(provider, index + 1) }
        }
        // EC keys are passed through unchanged
        val ecLeaf = generateAndroidFixture().fake.certificateChain.first()
        (ecLeaf.canonicalPublicKey() === ecLeaf.publicKey) shouldBe true
    }

    data("iOS ClientData carries ML-DSA keys (v2 wire)", mlDsaSets, nameFn = { _, it -> it.jcaName }) test { set ->
        val key = MlDsaJcaPrivateKey.generate(set).publicKey
        val challenge = Random.nextBytes(16)
        val clientData = IosHomebrewAttestation.ClientData(key, challenge)
        val json = clientData.prepareDigestInput()
        json.decodeToString() shouldContain "\"version\":2"
        // what Makoto does with it
        val parsed = IosHomebrewAttestation(attestation = byteArrayOf(), clientDataJSON = json).parsedClientData
        parsed shouldBe clientData
        parsed shouldBe IosHomebrewAttestation.ClientData(parsed.publicKey, challenge)
        parsed shouldNotBe IosHomebrewAttestation.ClientData(MlDsaJcaPrivateKey.generate(set).publicKey, challenge)
        parsed.publicKey.toJcaPublicKey().encoded.contentEquals(key.asn1.toDer()) shouldBe true
        StrictJson.decodeFromString<IosHomebrewAttestation.ClientData>(json.decodeToString()).publicKey shouldBe key
    }
}
