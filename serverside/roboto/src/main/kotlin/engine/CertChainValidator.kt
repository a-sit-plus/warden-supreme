package at.asitplus.attestation.android.engine

import at.asitplus.KmmResult
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.ConfigWithList
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlin.time.Instant

data class CertificateChainValidation(
    val verdict: KmmResult<GeneralizedSecurityLevel>,
    val revocationLists: List<ConfigWithList>,
)

interface CertChainValidator {
    @Throws(CertificateInvalidException::class, RevocationException::class)
    suspend fun CertificateChain.verifyCertificateChain(
        verificationDate: Instant,
        actualTrustAnchors: Collection<TrustedRoot>,
        requireRKP: Boolean,
    ): CertificateChainValidation

    val revocationCheckers: List<Pair<AndroidRevocationList.Loader.Configuration<*>, AndroidRevocationList.Loader>>
}
