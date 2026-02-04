package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.ConfigWithList
import at.asitplus.attestation.android.EternalX509Certificate
import at.asitplus.attestation.android.GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS
import at.asitplus.attestation.android.GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12
import at.asitplus.attestation.android.Roboto
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.attestation.android.isRemoteKeyProvisioned
import at.asitplus.attestation.wardenVersion
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.Security
import java.security.cert.CertPathValidator
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

interface CertChainValidator<T> {
    @Throws(CertificateInvalidException::class, RevocationException::class)
    suspend fun List<T>.verifyCertificateChain(
        verificationDate: Date,
        actualTrustAnchors: Collection<TrustedRoot>,
        requireRKP: Boolean
    )
    val revocationCheckers: List<Pair<AndroidRevocationList.Loader.Configuration<*>, AndroidRevocationList.Loader>>
    suspend fun revocationListsFromLastCall():  List<ConfigWithList>
}

