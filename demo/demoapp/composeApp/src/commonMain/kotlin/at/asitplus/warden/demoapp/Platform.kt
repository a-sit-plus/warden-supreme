package at.asitplus.warden.demoapp

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.signature
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform


@OptIn(ExperimentalTime::class)
internal suspend fun createJWT(alias: String, certChain: CertificateChain, nonce:String?=null): JwsSigned<JsonWebToken> {

    val signer = PlatformSigningProvider.getSignerForKey(alias).getOrThrow()


    val header = JwsHeader(
        algorithm = JwsAlgorithm.Signature.ES256,
        certificateChain = certChain
    )

    val token = JsonWebToken(
        subject = "Attested Client",
        issuedAt = Clock.System.now(),
        nonce = nonce
    )

    val signatureInput = JwsSigned.prepareJwsSignatureInput(header, Json.encodeToString(token).encodeToByteArray())
    val signature = signer.sign(signatureInput).signature

    val signed = JwsSigned(header = header, token, signature, signatureInput)

    println(signed.serialize())
    return signed

}