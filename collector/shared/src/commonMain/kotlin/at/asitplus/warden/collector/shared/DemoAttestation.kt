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

enum class CollectorPolicy(
    val label: String,
    val shortLabel: String,
    val description: String,
    val challengePath: String,
    val attestPath: String,
) {
    DEFAULT(
        "Default",
        "Default",
        "Requires timely certificate chains, a locked bootloader, and OEM verified boot.",
        DemoAttestation.CHALLENGE_PATH,
        DemoAttestation.ATTEST_PATH,
    ),
    OLD_FACTORY_CERTIFICATES(
        "Trust old factory certs",
        "Old certs",
        "Accepts expired factory-provisioned certificate chains, but otherwise keeps the default policy.",
        "/api/v1/old-factory-certs/challenge",
        "/api/v1/old-factory-certs/attest",
    ),
    UNLOCKED_BOOTLOADER(
        "Unlocked Bootloader",
        "Unlocked",
        "Accepts expired factory-provisioned chains and unlocked bootloaders; verified boot state and boot-key checks are skipped.",
        "/api/v1/unlocked-bootloader/challenge",
        "/api/v1/unlocked-bootloader/attest",
    ),
    GRAPHENE_OS(
        "Strongbox-only and GrapheneOS",
        "GrapheneOS",
        "Accepts only strongbox-capable devices, but trusts expired factory-provisioned chains and locked devices using OEM verified boot or a pinned GrapheneOS verified boot key.",
        "/api/v1/grapheneos/challenge",
        "/api/v1/grapheneos/attest",
    ),
    STRONGBOX_ONLY(
        "StrongBox only",
        "StrongBox",
        "Uses the default policy and additionally requires the attested key to be backed by StrongBox.",
        "/api/v1/strongbox/challenge",
        "/api/v1/strongbox/attest",
    ),
}
