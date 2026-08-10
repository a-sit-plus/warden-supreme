import at.asitplus.attestation.android.*
import at.asitplus.catchingUnwrapped
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.testballoon.matrix.CompactReport
import at.asitplus.testballoon.matrix.matrixSuite
import com.android.keyattestation.verifier.KeyDescription
import com.google.android.attestation.ParsedAttestationRecord
import io.kotest.assertions.fail
import io.kotest.assertions.withClue
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DEROctetString
import java.io.ByteArrayInputStream
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.io.bufferedReader
import kotlin.io.forEachLine
import kotlin.io.println
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.use

private typealias DebugDetails = Pair<Instant, ByteArray>

val DebugDetails.verificationTime get() = first
val DebugDetails.challenge get() = second

private typealias DebugStmt = Triple<List<String>, AndroidAttestationConfiguration, DebugDetails>

val DebugStmt.certificateChain get() = first
val DebugStmt.cfg get() = second
val DebugStmt.details get() = third


@OptIn(ExperimentalAtomicApi::class)
val DebugStatementParserTest by matrixSuite {
    val json = Json { ignoreUnknownKeys = true }
    val classLoader = Thread.currentThread().contextClassLoader


    val proofs: List<DebugStmt> =
        catchingUnwrapped {
            classLoader.getResourceAsStream("DebugStatements.csv").bufferedReader(Charsets.UTF_8).use {

                val lst = mutableListOf<DebugStmt>()
                it.forEachLine { line ->
                    catchingUnwrapped {
                        val parsed =
                            json.parseToJsonElement(MultiBase.decode(line.trim())!!.decodeToString()).jsonObject
                        val timestamp =
                            catchingUnwrapped { Instant.parse(parsed.getValue("verificationTime").jsonPrimitive.content) }.getOrNull()
                                ?: Instant.fromEpochMilliseconds(parsed.getValue("verificationTime").jsonPrimitive.content.toLong())
                        val offset = Duration.parse(parsed.getValue("verificationTimeOffset").jsonPrimitive.content)
                        val challenge =
                            parsed.getValue("challenge").jsonPrimitive.content.decodeToByteArray(Base64UrlStrict)
                        val androidApp =
                            parsed.getValue("androidAttestationConfiguration").jsonObject.getValue("applications").jsonArray.first().jsonObject
                        val pkg = androidApp.getValue("packageName").jsonPrimitive.content

                        val digests = (catchingUnwrapped { androidApp.getValue("signatureDigests")}.getOrNull()
                            ?: androidApp.getValue("signerFingerprints")).jsonArray.map {
                            catchingUnwrapped { it.jsonPrimitive.content.decodeToByteArray(Base64UrlStrict) }.getOrNull()
                                ?: it.jsonPrimitive.content.parseHex()
                        }.toSet()

                        val attestationCfg =
                            AndroidAttestationConfiguration(
                                AndroidAttestationConfiguration.AppData(pkg, digests),
                                ignoreLeafValidity = true,
                                verificationSecondsOffset = offset.inWholeSeconds
                            )
                        val chain =
                            (parsed.getValue("genericAttestationProof").jsonArray).map { it.jsonPrimitive.content }
                        lst += DebugStmt(chain, attestationCfg, DebugDetails(timestamp, challenge))
                    }.getOrElse { println(line) }
                }
                lst

            }
        }.getOrElse {
            emptyList()
        }

    if (proofs.isEmpty()) {
        if (System.getenv("NO_PRIVATE_TEST_DATA") != "true")

            "NO PRIVATE TEST DATA PRESENT. Fine for CI, but not for local tests" {
                fail("NO PRIVATE TEST DATA PRESENT")
            }

        "No private test data present" {}
        return@matrixSuite
    }

    compact("${proofs.size} collected real-world proofs") { report = CompactReport.FailuresOnly } - {
        val erroneous = AtomicInteger(0)
        data(
            proofs.withIndex().toList(),
            nameFn = { _, value -> "${value.index}: ${value.value.first.size} certs" }) - { (index, it) ->
            val attestationCertChain =
                it.certificateChain.map {
                    val certBytes = Base64.getUrlDecoder().decode(it)
                    catchingUnwrapped {
                        certificateFactory.generateCertificate(
                            ByteArrayInputStream(
                                certBytes
                            )
                        ) as X509Certificate
                    }.getOrNull()
                }.filterNotNull()

            if (attestationCertChain.isNotEmpty()) {


                val androidAttestationExtension = attestationCertChain.first().androidAttestationExtension
                "from chain should be same as from leaf" {
                    androidAttestationExtension shouldBe attestationCertChain.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }?.androidAttestationExtension
                }
                "convert" - {
                    data(
                        "certificates",
                        attestationCertChain,
                        nameFn = { _, value -> value.subjectX500Principal.toString() }) test {
                        it.toKmpCertificate().isSuccess shouldBe true

                        var own = it.toKmpCertificate().getOrThrow()
                        if (!own.encodeToDer().contentEquals(it.encoded)) {
                            System.err.println("OWN: ${own.encodeToDer().toHexString()}")
                            System.err.println("ORI: ${it.encoded.toHexString()}")
                        }
                        own.encodeToDer() shouldBe it.encoded
                    }
                }

                if (index > 0) {
                    val prev = proofs[index - 1].certificateChain.map {
                        val certBytes = Base64.getUrlDecoder().decode(it)
                        catchingUnwrapped {
                            certificateFactory.generateCertificate(
                                ByteArrayInputStream(
                                    certBytes
                                )
                            ) as X509Certificate
                        }.getOrNull()
                    }.filterNotNull()

                    if (prev.isNotEmpty() && ((androidAttestationExtension != null) && prev.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }?.androidAttestationExtension != null)) {
                        "concatenating two chains (current = $index) should get the same exnt as just from the current chain" {
                            //leaf = fist in chain, root = last in chain. so we went the closest to CURRENT root. hence we need to prepent
                            //s.t. the chain gets extended below the leaf and not above the root
                            (prev + attestationCertChain).closestToRoot { it.hasAndroidKeyAttestationExtensionOid }.androidAttestationExtension shouldBe attestationCertChain.closestToRoot { it.hasAndroidKeyAttestationExtensionOid }.androidAttestationExtension
                        }
                    }
                }

                val fromGoogle =
                    catchingUnwrapped { ParsedAttestationRecord.createParsedAttestationRecord(attestationCertChain) }.getOrNull()

                "Own" {
                    if (fromGoogle == null) {
                        System.err.println("Old Google parser glitched out")
                        val newParser = attestationCertChain.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }
                            ?.let { catchingUnwrapped { KeyDescription.parseFrom(it) }.getOrNull() }

                        if (newParser == null) {
                            attestationCertChain.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }
                            .shouldBeNull()
                            return@invoke//well, well, well…}
                        }
                    }
                    androidAttestationExtension.shouldNotBeNull()
                    attestationCertChain.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }
                        .shouldNotBeNull().androidAttestationExtension shouldBe androidAttestationExtension
                    catchingUnwrapped {

                        val reencoded = androidAttestationExtension.encodeToDer()
                        val original = (DEROctetString.fromByteArray(
                            attestationCertChain.first().getExtensionValue(
                                AttestationKeyDescription.oid.toString()
                            )
                        ) as ASN1OctetString).octets
                        if (!reencoded.contentEquals(original)) {
                            System.err.println("OWN: ${reencoded.toHexString()}")
                            System.err.println("ORI: ${original.toHexString()}")
                        }
                        reencoded shouldBe original

                    }.getOrElse {
                        throw it
                    }
                    if (fromGoogle != null) assertSemanticallyEqual(fromGoogle, androidAttestationExtension)

                }
                "Roboto Engine Check" - {
                    val stmt = it
                    //not only is revocation slow. it will also have us run into rate limits
                    //plus, many have been revoked and we also want success results!
                    val rSupreme = stmt.cfg.copy(supremeParser = true, revocation = emptyList())
                    val rLegacy = stmt.cfg.copy(supremeParser = false, revocation = emptyList())

                    data(
                        "config pairs",
                        listOf(
                            rSupreme to rLegacy,
                            rSupreme.copy(patchLevel = PatchLevel(2025, 1)) to
                                    rLegacy.copy(patchLevel = PatchLevel(2025, 1)),
                            rSupreme.copy(patchLevel = null, androidVersion = null) to
                                    rLegacy.copy(patchLevel = null, androidVersion = null),
                            rSupreme.copy(requireRemoteKeyProvisioning = true) to rLegacy.copy(
                                requireRemoteKeyProvisioning = true
                            ),
                            rSupreme.copy(ignoreLeafValidity = false) to rLegacy.copy(ignoreLeafValidity = false),
                            rSupreme.copy(requireStrongBox = true) to rLegacy.copy(requireStrongBox = true),
                            rSupreme.copy(enableSoftwareAttestation = true) to rLegacy.copy(
                                enableSoftwareAttestation = true
                            ),
                            rSupreme.copy(allowBootloaderUnlock = true) to rLegacy.copy(allowBootloaderUnlock = true),
                            //get the "UnknownPackage" one step further
                            rSupreme.copy(
                                applications = listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        "UnknownPackage",
                                        signerFingerprints = setOf(byteArrayOf())
                                    )
                                )
                            ) to rLegacy.copy(
                                applications = listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        "UnknownPackage",
                                        signerFingerprints = setOf(byteArrayOf())
                                    )
                                )
                            )
                        )
                    ) test { (rSupreme, rLegacy) ->
                        val supreme = Roboto(rSupreme).verify(
                            attestationCertChain,
                            stmt.details.verificationTime,
                            stmt.details.challenge
                        )
                        val legacy = Roboto(rLegacy).verify(
                            attestationCertChain,
                            stmt.details.verificationTime,
                            stmt.details.challenge
                        )

                        //needs toString, because types inside result differ on error
                        withClue("Supreme success: ${supreme.isSuccess}, Legacy success: ${legacy.isSuccess}") {
                            if (fromGoogle == null) {
                                if (runCatching {
                                        ParsedAttestationRecord.createParsedAttestationRecord(
                                            attestationCertChain
                                        )
                                    }.exceptionOrNull()?.message?.startsWith("Multiple authorization list entries for tag") != true)
                                    supreme.isFailure.shouldBeTrue()
                                else {
                                    erroneous.incrementAndGet()
                                    System.err.println(attestationCertChain.closestToRootOrNull { it.hasAndroidKeyAttestationExtensionOid }
                                        ?.let { Base64.getEncoder().encodeToString(it.encoded) }
                                        ?: "NO attestation cert found")
                                }
                            } else supreme.toString() shouldBe legacy.toString()
                        }
                    }
                }
            } else "Empty chain" {}
        }
        println("Number of erroneous attestation proofs: " + erroneous.get())
    }
}
