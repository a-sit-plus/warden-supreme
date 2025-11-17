package at.asitplus.warden

import at.asitplus.signum.indispensable.toJcaCertificate
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.sign.Signer
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.server.application.*
import io.ktor.server.auth.*
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import java.io.FileInputStream
import java.security.KeyStore
import java.security.Security
import java.security.cert.*
import java.security.interfaces.ECKey
import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration


fun Application.configureSecurity() {
    val logger = log
    val caCert = CA_CERT
    authentication {
        bearer("jwt") { //we are doing custom JWT auth for demonstration purposes

            //allow for out-of-sync clocks between backend and mobile client
            val offset = runCatching {
                this@configureSecurity.environment.config.property("jwt.drift-minutes").getString().toLong()
            }.getOrElse { 0L }.minutes.toJavaDuration()
            logger.info("Temporal offset for JWT verification: $offset")

            authenticate { tokenCredential ->
                runCatching {
                    //First parse the JWT to ensure it is structurally correct (signed, payload not detached)
                    logger.info("Parsing jwt ${tokenCredential.token}")
                    SignedJWT.parse(tokenCredential.token)?.let { jwt ->

                        //now we verify it cryptographically, check its validity and extract the leaf cert's subject,
                        caCert.verifyJWTAndExtractSignerSubject(jwt, offset, logger)?.let {
                            //since we use the extracted subject to identify the client
                            UserIdPrincipal(it)
                        }
                    }
                }.getOrElse { it.printStackTrace(); null }
            }
        }
    }
}

private suspend fun at.asitplus.signum.indispensable.pki.X509Certificate.verifyJWTAndExtractSignerSubject(
    jwt: SignedJWT,
    offset: Duration,
    logger: Logger
): String? = runCatching {


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

    bindingCert.subjectDN.name
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