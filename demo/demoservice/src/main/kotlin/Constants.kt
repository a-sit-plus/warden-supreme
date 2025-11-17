package at.asitplus.warden

import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import io.ktor.server.application.*

val Application.ENDPOINT_CHALLENGE get() = "/api/v1/challenge"
val Application.PATH_ATTEST get() = "/api/v1/attest"
val Application.ENDPOINT_ATTEST get() = "http://10.0.2.2:8080$PATH_ATTEST"

val Application.subjectName
    get() = listOf(
        RelativeDistinguishedName(
            AttributeTypeAndValue.CommonName(
                Asn1String.UTF8("Supreme Client")
            )
        )
    )
