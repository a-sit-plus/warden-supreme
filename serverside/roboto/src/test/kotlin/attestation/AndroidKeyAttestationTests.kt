@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.attestation.android.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration.AppData
import at.asitplus.attestation.android.AttestationEngine
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyHardwareAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacyNougatHybridAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.LegacySoftwareAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.SignumHardwareAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.SignumNougatHybridAttestationEngine
import at.asitplus.attestation.android.at.asitplus.attestation.android.legacy.SignumSoftwareAttestationEngine
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.data.AttestationData
import at.asitplus.attestation.data.AttestationData.Level
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.util.encoders.Base64
import org.opentest4j.TestAbortedException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import at.asitplus.signum.indispensable.pki.X509Certificate as SigNumX509


@OptIn(ExperimentalStdlibApi::class)
class AndroidKeyAttestationTests : FreeSpec({

    @Serializable
    data class AppPkg(
        val name: String,
        val version: String? = null
    )

    @Serializable
    data class RootOfTrust(
        val verifiedBootState: String? = null,
        val deviceLocked: Boolean? = null,
    )

    @Serializable
    data class HardwareEnforced(
        val rootOfTrust: RootOfTrust? = null
    )

    @Serializable
    data class AttestationApplicationId(
        val packages: List<AppPkg> = emptyList(),
        val signatures: List<String> = emptyList() // base64 digests
    )

    @Serializable
    data class SoftwareEnforced(
        val creationDateTime: String, // millis as string
        val attestationApplicationId: AttestationApplicationId
    )

    @Serializable
    data class AttestationJson(
        val attestationChallenge: String,
        val attestationSecurityLevel: String,
        val keyMintSecurityLevel: String,
        val softwareEnforced: SoftwareEnforced? = null,
        val hardwareEnforced: HardwareEnforced? = null
    )

    fun readString(p: Path): String = Files.readString(p, StandardCharsets.UTF_8)

    fun loadPemChain(pemText: String): List<X509Certificate> {
        val re = Regex(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)
        )
        return re.findAll(pemText).map { m ->
            SigNumX509.decodeFromPem(m.value).getOrThrow().toJcaCertificateBlocking().getOrThrow()
        }.toList()
    }

    fun mapSecurityLevel(keymasterLevel: String, attestationLevel: String): AttestationData.Level =
        if (keymasterLevel != attestationLevel) AttestationData.Level.NOUGAT
        else when (keymasterLevel.uppercase()) {
            "SOFTWARE" -> AttestationData.Level.SOFTWARE
            else -> AttestationData.Level.HARDWARE
        }

    data class Case(
        val name: String,
        val jsonPath: Path,
        val pemPath: Path,
        val model: AttestationJson
    )
    System.out.println(System.getProperty("user.dir"));

    val root = Paths.get("..","..", "dependencies", "keyattestation", "testdata")
    val jsonFiles = Files.walk(root)
        .filter { it.toString().endsWith(".json") }
        .toList()
        .sorted()

    // build cases (json + matching pem with same basename)
    val cases: List<Case> = jsonFiles.map { jsonPath ->
        val rel = root.relativize(jsonPath)                 // <-- relativ zum Root
        val relStr = rel.toString().replace('\\', '/')      // Windows -> Slashes
        val pemPath = jsonPath.parent.resolve(rel.fileName.toString().substringBeforeLast(".json") + ".pem")
        check(Files.exists(pemPath)) { "PEM chain missing for $jsonPath" }

        val json = Json { ignoreUnknownKeys = true }
            .decodeFromString<AttestationJson>(readString(jsonPath))

        Case(name = relStr, jsonPath = jsonPath, pemPath = pemPath, model = json)
    }

    "Android Key Attestation corpus (${cases.size} cases)" - {
        withData(cases) { c ->
            println("run test: " + c.name)
            // 1) cert chain
            val chain = loadPemChain(readString(c.pemPath))
            chain.shouldNotBeNull()
            chain.isNotEmpty() shouldBe true

            // sanity: our DER roundtrip
            chain.forEach { cert ->
                val der = cert.encoded
                val parsed = SigNumX509.decodeFromDer(der)
                parsed.encodeToDer() shouldBe der
            }

            // 2) extract appId digest + pkg
            val pkgName = c.model.softwareEnforced?.attestationApplicationId?.packages?.firstOrNull()?.name
                ?: "unknown.package" // fallback
            val expectedDigest: ByteArray = c.model.softwareEnforced
                ?.attestationApplicationId?.signatures?.firstOrNull()
                ?.let { Base64.decode(it) }
                ?: ByteArray(0) // fallback (won't match anyway)

            // 3) challenge + time
            val challenge = Base64.decode(c.model.attestationChallenge)
            val creationMillis = c.model.softwareEnforced?.creationDateTime?.toLongOrNull()
            val iso = creationMillis?.let {Instant.ofEpochMilli(it) }
            val verificationDate: Date = creationMillis?.let { Date(it) } ?: Date()

            // 4) level + expected outcome

            // TODO Manfred 02.09.2025: not sure how to set level correctly
            val level =
                c.model.keyMintSecurityLevel // gives "CertificateInvalidException: No matching root certificate"
            val aLevel =
                c.model.attestationSecurityLevel // gives "AttestationValueException: Keymaster security level not software"

            val verifiedBootState = c.model.hardwareEnforced?.rootOfTrust?.verifiedBootState?.uppercase()
            val deviceLocked = c.model.hardwareEnforced?.rootOfTrust?.deviceLocked

            println("${c.name}: verifiedBootState=$verifiedBootState level=${level} iso=$iso")

            // 5) build checker
            val legacyChecker = legacyAttestationService(
                attestationLevel = mapSecurityLevel(level, aLevel),
                androidPackageName = pkgName,
                androidAppSignatureDigest = listOf(expectedDigest),
                // optional: requireStrongBox = (c.model.attestationSecurityLevel?.uppercase() == "STRONG_BOX"),
                attestationStatementValidity = Duration.parse("5m")
            )
            val signumChecker = signumAttestationService(
                attestationLevel = mapSecurityLevel(level, aLevel),
                androidPackageName = pkgName,
                androidAppSignatureDigest = listOf(expectedDigest),
                // optional: requireStrongBox = (c.model.attestationSecurityLevel?.uppercase() == "STRONG_BOX"),
                attestationStatementValidity = Duration.parse("5m")
            )

            if (verifiedBootState == "UNVERIFIED") {
                val ex = shouldThrow<AttestationValueException> {
                    legacyChecker.verifyAttestation(chain, verificationDate, challenge)
                }
                if (ex.message == "Bootloader not locked") {
                    deviceLocked shouldBe false
                } else {
                    throw TestAbortedException("UNVERIFIED : unknown case")
                }
            } else {
                legacyChecker.verifyAttestation(chain, verificationDate, challenge)
            }
        }
    }
})

// TODO: move somewhere else? not used here!
// TODO checkout AndroidAttestationConfiguration.legacyEngineForLevel
fun legacyAttestationService(
    attestationLevel: Level,
    androidPackageName: String,
    androidAppSignatureDigest: List<ByteArray>,
    androidVersion: Int? = null,
    androidAppVersion: Int? = null,
    androidPatchLevel: PatchLevel? = null,
    requireStrongBox: Boolean = false,
    unlockedBootloaderAllowed: Boolean = false,
    requireRollbackResistance: Boolean = false,
    attestationStatementValidity: Duration = 5.minutes
) : AttestationEngine<ParsedAttestationRecord, AuthorizationList> {
    val appData = AppData(
        packageName = androidPackageName,
        signatureDigests = androidAppSignatureDigest,
        appVersion = androidAppVersion
    )
    return when (attestationLevel) {
        Level.HARDWARE -> LegacyHardwareAttestationEngine(
            AndroidAttestationConfiguration(
                appData,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true
            )
        )

        Level.SOFTWARE -> LegacySoftwareAttestationEngine(
            AndroidAttestationConfiguration(
                appData,
                disableHardwareAttestation = true,
                enableSoftwareAttestation = true,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true,
            )
        )

        Level.NOUGAT -> LegacyNougatHybridAttestationEngine(
            AndroidAttestationConfiguration(
                appData,
                disableHardwareAttestation = true,
                enableNougatAttestation = true,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true
            )
        )
    }
}

fun signumAttestationService(
    attestationLevel: Level,
    androidPackageName: String,
    androidAppSignatureDigest: List<ByteArray>,
    androidVersion: Int? = null,
    androidAppVersion: Int? = null,
    androidPatchLevel: PatchLevel? = null,
    requireStrongBox: Boolean = false,
    unlockedBootloaderAllowed: Boolean = false,
    requireRollbackResistance: Boolean = false,
    attestationStatementValidity: Duration = 5.minutes
) : AttestationEngine<ParsedAttestationRecord, AuthorizationList> {
    val singleApp = AppData(
        packageName = androidPackageName,
        signatureDigests = androidAppSignatureDigest,
        appVersion = androidAppVersion
    )
    return when (attestationLevel) {
        Level.HARDWARE -> SignumHardwareAttestationEngine(
            AndroidAttestationConfiguration(
                singleApp,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true
            )
        )

        Level.SOFTWARE -> SignumSoftwareAttestationEngine(
            AndroidAttestationConfiguration(
                singleApp,
                disableHardwareAttestation = true,
                enableSoftwareAttestation = true,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true,
            )
        )

        Level.NOUGAT -> SignumNougatHybridAttestationEngine(
            AndroidAttestationConfiguration(
                singleApp,
                disableHardwareAttestation = true,
                enableNougatAttestation = true,
                androidVersion = androidVersion,
                patchLevel = androidPatchLevel,
                requireStrongBox = requireStrongBox,
                allowBootloaderUnlock = unlockedBootloaderAllowed,
                requireRollbackResistance = requireRollbackResistance,
                attestationStatementValiditySeconds = attestationStatementValidity.inWholeSeconds,
                ignoreLeafValidity = true
            )
        )
    }
}
