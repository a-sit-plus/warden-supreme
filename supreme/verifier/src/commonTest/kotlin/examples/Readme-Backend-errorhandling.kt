package docs.service.callbacks

import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.IosAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import docs.config.minimal.verifier
import java.util.logging.Level
import java.util.logging.Logger

private val csr: Pkcs10CertificationRequest = TODO()
private val logger = Logger.getLogger("demo")
//@formatter:off
private suspend fun foo() {


    val result = verifier.verifyAttestation(
        csr = csr,
        onAttestationError = { debugStatement ->
         /*(1)!*/logger.log(Level.WARNING, debugStatement.serializeCompact(), cause)
            when (cause) {
             /*(2)!*/is AttestationException.Certificate.Time    -> TODO()
             /*(3)!*/is AttestationException.Certificate.Trust   -> TODO()
             /*(4)!*/is AttestationException.Configuration       -> TODO()
                is AttestationException.Content.Android ->
                    when ((cause as AttestationException.Content.Android).cause.reason) {
                     /*(5)!*/AttestationValueException.Reason.OS_VERSION          -> TODO()
                     /*(6)!*/AttestationValueException.Reason.STATEMENT_TIME      -> TODO()
                     /*(7)!*/AttestationValueException.Reason.CHALLENGE           -> TODO()
                     /*(8)!*/AttestationValueException.Reason.PACKAGE_NAME        -> TODO()
                     /*(9)!*/AttestationValueException.Reason.APP_SIGNER_DIGEST   -> TODO()
                     /*(10)!*/AttestationValueException.Reason.APP_VERSION         -> TODO()
                     /*(11)!*/AttestationValueException.Reason.ROLLBACK_RESISTANCE -> TODO()
                     /*(12)!*/AttestationValueException.Reason.SEC_LEVEL           -> TODO()
                     /*(13)!*/AttestationValueException.Reason.SYSTEM_INTEGRITY    -> TODO()
                     /*(14)!*/AttestationValueException.Reason.APP_UNEXPECTED      -> TODO()
                    }
                is AttestationException.Content.iOS     ->
                    when ((cause as AttestationException.Content.iOS).cause.reason) {
                     /*(15)!*/IosAttestationException.Reason.OS_VERSION            -> TODO()
                     /*(16)!*/IosAttestationException.Reason.STATEMENT_TIME        -> TODO()
                     /*(17)!*/IosAttestationException.Reason.CHALLENGE             -> TODO()
                     /*(18)!*/IosAttestationException.Reason.IDENTIFIER            -> TODO()
                     /*(19)!*/IosAttestationException.Reason.SIG_CTR               -> TODO()
                     /*(20)!*/IosAttestationException.Reason.APP_UNEXPECTED        -> TODO()
                }
             /*(21)!*/is AttestationException.Content.Unknown -> TODO("Unsupported Input")
            }
        }
    ) { TODO("Refer to minimum example for certificate issuance") }












}
