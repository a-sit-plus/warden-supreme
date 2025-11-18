package at.asitplus.warden

import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.attestation.supreme.deviceName
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.toJcaCertificate
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import io.ktor.util.encodeBase64
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import java.io.FileInputStream
import java.security.KeyStore
import java.security.Security
import java.security.cert.*
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.time.Duration
import java.time.Instant
import kotlin.random.Random
import kotlin.text.toCharArray
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


enum class AttestationLevel {
    HARDWARE, SOFTWARE
}

@OptIn(ExperimentalTime::class)
fun Application.configureSecurity() {
    val offset = runCatching {
        this@configureSecurity.environment.config.property("jwt.drift-minutes").getString().toLong()
    }.getOrElse { 0L }.minutes.toJavaDuration()

    val nonceGen = NonceGen(Clock.System, offset.toKotlinDuration())
    val logger = log
    val caCert = CA_CERT
    authentication {
        this.bearer("demojwt") { //we are doing custom JWT auth for demonstration purposes
            //allow for out-of-sync clocks between backend and mobile client

            logger.info("Temporal offset for JWT verification: $offset")

            authenticate { tokenCredential ->
                runCatching {
                    //First parse the JWT to ensure it is structurally correct (signed, payload not detached)
                    logger.info("Parsing jwt ${tokenCredential.token}")
                    SignedJWT.parse(tokenCredential.token)?.let { jwt ->

                        //now we verify it cryptographically, check its validity and extract the leaf cert's subject,
                        caCert.verifyJWTAndExtractSignerSubject(jwt, offset, logger)?.let { (securityLevel, nonce) ->
                            //since we use the extracted subject to identify the client

                            if (nonce == null) {
                                throw ChallengeException(nonceGen.generate())
                            }
                            if (!nonceGen.validate(nonce)) {
                                throw RuntimeException("Invalid nonce $nonce")
                            }

                            securityLevel
                        }
                    }
                }.getOrElse {

                    if (it is ChallengeException) throw it

                    it.printStackTrace(); null
                }
            }
        }
    }

    install(StatusPages) {
        exception<ChallengeException> { call, cause ->
            call.respondText(text = cause.challenge, status = HttpStatusCode.Forbidden)
        }
        exception<Throwable> { call, cause ->
            this@configureSecurity.log.error(cause.message ?: "Unknown error", cause)
            call.respondText(text = "500: $cause", status = HttpStatusCode.InternalServerError)
        }
        status(HttpStatusCode.Unauthorized) { call, cause ->
            val html =
                this::class.java.classLoader.getResourceAsStream("unauthorized-forbidden.html").reader().readText()
            call.respondText(html, ContentType.Text.Html)
        }
    }
}


class ChallengeException(val challenge: String) : RuntimeException()



private suspend fun at.asitplus.signum.indispensable.pki.X509Certificate.verifyJWTAndExtractSignerSubject(
    jwt: SignedJWT,
    offset: Duration,
    logger: Logger
): Pair<AttestationLevel, String?>? = catchingUnwrapped {


    //PARSE JWT

    val jwtClaimsSet: JWTClaimsSet = jwt.jwtClaimsSet


    //CHECK IT INCLUDES x5c
    val header = jwt.header
    val x509CertChain = header.x509CertChain?.let { X509CertChainUtils.parse(it) }
        ?: throw SecurityException("No certificates found in JWT header")
    logger.info(
        "JWT contains certificate chain of length ${x509CertChain.size}:\n\n${
            x509CertChain.joinToString(
                separator = "\n"
            ) { "-----BEGIN CERTIFICATE-----\n$it\n-----END CERTIFICATE-----\n" }
        }"
    )
    //Verify that the root corresponds to our singing cert
    if (!x509CertChain.last().encoded.contentEquals(this.encodeToDer())) throw SecurityException("Signed by wrong root")

    logger.info("root cert is ours")

    //get the binding cert
    val bindingCert = x509CertChain.first()

    //CHECK IF CERT USES EC
    if (bindingCert.publicKey !is ECKey) throw SecurityException("binding cert not EC")
    val algorithm = header.algorithm

    //ONLY EC in spec, but we need to check, obviously
    if (!JWSAlgorithm.Family.EC.contains(algorithm)) throw SecurityException("Incorrect EC Algorithm name in JWT: ${algorithm.name}")

    logger.info("Binding Cert uses EC (${algorithm.name})")

    val verificationKey = com.nimbusds.jose.jwk.ECKey.parse(bindingCert)

    logger.info("Binding key: ${verificationKey.toJSONString()}")

    //we know this is EC, so here we go
    if (!jwt.verify(ECDSAVerifier(verificationKey))) throw SecurityException("Could not verify JWT")
    logger.info("JWT cryptographically verified")

    //check expiry
    if (jwtClaimsSet.issueTime.toInstant().plus(Duration.ofMinutes(15).plus(offset))
            .isBefore(Instant.now())
    ) throw SecurityException("JWT expired")

    logger.info("JWT is less than 15 minutes (+$offset) old.")

    if (jwtClaimsSet.issueTime.toInstant()
            .isAfter(Instant.now().plus(offset))
    ) throw SecurityException("JWT not yet valid")
    logger.info("JWT is already valid too")

    val cf = CertificateFactory.getInstance("X.509")
    val path = cf.generateCertPath(x509CertChain)
    val validator = CertPathValidator.getInstance("PKIX")

    val params = PKIXParameters(setOf(TrustAnchor(this.toJcaCertificate().getOrThrow(), null))).apply {
        isRevocationEnabled = false //🎶 We don't need no revocation! 🎶
    }
    val r = validator.validate(path, params) as PKIXCertPathValidatorResult
    logger.info("JWT certificate chain verification successful")

    //we issued this cert so we can trust the extension is only present for hardware-attested devices
    val level = if (bindingCert.toKmpCertificate()
            .getOrThrow().tbsCertificate.extensions?.firstOrNull { it.oid == HW_OID } != null
    ) AttestationLevel.HARDWARE else AttestationLevel.HARDWARE
    level to jwtClaimsSet.getStringClaim("nonce")
}.getOrElse { it.printStackTrace(); null }


private lateinit var _caCert: at.asitplus.signum.indispensable.pki.X509Certificate
private lateinit var _signer: Signer
fun Application.loadKeyStore() {
    Security.addProvider(BouncyCastleProvider())
    val ks = FileInputStream("ca.p12").use { fin ->
        KeyStore.getInstance("PKCS12").also { it.load(fin, "changeit".toCharArray()) }
    }

    _caCert = (ks.getCertificate("ca") as X509Certificate).toKmpCertificate().getOrThrow()

    _signer =
        runBlocking {
            JKSProvider { withBackingObject { store = ks } }.getOrThrow().getSignerForKey("ca") {
                privateKeyPassword = "changeit".toCharArray()
            }.getOrThrow()
        }
}

val Application.CA_CERT get() = _caCert
val Application.SIGNER get() = _signer


@OptIn(ExperimentalTime::class)
class NonceGen(private val clock: Clock, private val offset: kotlin.time.Duration) {

    private val mutex = Mutex()

    private val challengesByNonce = mutableMapOf<String, kotlin.time.Instant>()

    suspend fun generate(): String {
        mutex.withLock {
            pruneExpiredEntries()
            val nonce = WardenDefaults.nonceGenerator().encodeBase64()
            // Strong cryptographic nonces make collisions unrealistic, so we simply overwrite
            challengesByNonce[nonce] = clock.now() + 5.minutes + offset
            return nonce
        }
    }

    suspend fun validate(nonce: String): Boolean {
        mutex.withLock {
            pruneExpiredEntries()
            return find(nonce)
        }
    }

    private fun find(nonce: String): Boolean {
        challengesByNonce.remove(nonce) ?: return false

        return true
    }

    private fun pruneExpiredEntries() {
        // Capture time once per call instead of per-entry
        val nowWithOffset = clock.now() + offset

        val iterator = challengesByNonce.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value <= nowWithOffset) {
                iterator.remove()
            }
        }
    }
}

@OptIn(ExperimentalUuidApi::class)
val HW_OID = ObjectIdentifier(Uuid.parse("f156054d-b923-43fc-b4dd-f8aeff4951ba"))

@OptIn(ExperimentalTime::class)
suspend fun Signer.issueCertificate(
    csr: Pkcs10CertificationRequest,
    caCert: at.asitplus.signum.indispensable.pki.X509Certificate,
    isHardware: Boolean = false
): CertificateChain {
    val leafCertificate = sign(
        TbsCertificate(
            serialNumber = Random.nextBytes(32),
            publicKey = csr.tbsCsr.publicKey,
            signatureAlgorithm = signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
            validFrom = Asn1Time(Clock.System.now()),
            validUntil = Asn1Time(Clock.System.now() + 10.days),
            issuerName = caCert.tbsCertificate.subjectName,
            subjectName = listOf(
                RelativeDistinguishedName(
                    AttributeTypeAndValue.CommonName(
                        Asn1String.UTF8("Attested Client: ${csr.deviceName}")
                    )
                )
            ),
            extensions = if (isHardware) listOf(
                X509CertificateExtension(
                    HW_OID,
                    critical = false,
                    Asn1PrimitiveOctetString(byteArrayOf())
                )
            ) else listOf()
        )
    ).getOrThrow()
    return listOf(leafCertificate, caCert)
}

