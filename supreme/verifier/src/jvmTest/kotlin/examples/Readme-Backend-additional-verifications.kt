package examples.docs.service.additionalverifications

import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import examples.docs.config.minimal.verifier

private val csr: Pkcs10CertificationRequest = TODO()
private val expectedTenant = "tenant-a"

private suspend fun issueCertificateChain(csr: Pkcs10CertificationRequest): CertificateChain = TODO()

private suspend fun foo() {



val response = verifier.verifyAttestation(
 /*(1)!*/csr = csr,
 /*(2)!*/additionalVerifications = { receivedCsr, verifiedAttestation ->
        val tenant = /*(3)!*/additionalPayload?.get("tenant")?.toString()
        if (tenant != expectedTenant) {
         /*(4)!*/AttestationResponse.Failure(
                AttestationResponse.Failure.Type.CONTENT,
                "Attestation challenge does not match tenant policy"
            )
        } else {
         /*(5)!*/null
        }
    },
 /*(6)!*/certificateIssuer = { verifiedCsr ->
        issueCertificateChain(verifiedCsr)
    }
)



}
