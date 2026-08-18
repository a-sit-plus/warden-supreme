package at.asitplus.warden.collector.shared

/**
 * Contract shared between the collector app (client) and the collector backend (verifier).
 *
 * Keeping the endpoint paths here guarantees both sides agree, since
 * [at.asitplus.warden.collector.shared] depends on `supreme-common`, the app adds `supreme-client`
 * and the backend adds `supreme-verifier`.
 *
 * Both sides use real system time; the verifier's default `verificationTimeOffset` leeway absorbs
 * normal client/server clock skew.
 */
object DemoAttestation {

    /** GET endpoint the app fetches the attestation challenge from. */
    const val CHALLENGE_PATH: String = "/api/v1/challenge"

    /** GET endpoint exposing the version code of the bundled Android app. */
    const val VERSION_PATH: String = "/api/v1/version"

    /** Download path of the release APK embedded in the backend. */
    const val DOWNLOAD_PATH: String = "/collector.apk"

    /** POST endpoint the app submits the attestation proof to (embedded in the challenge by the backend). */
    const val ATTEST_PATH: String = "/api/v1/attest"
}
