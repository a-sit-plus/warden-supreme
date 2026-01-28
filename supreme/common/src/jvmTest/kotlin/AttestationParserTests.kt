import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import com.google.android.attestation.ParsedAttestationRecord
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DEROctetString
import java.io.ByteArrayInputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

private val certificateFactory = CertificateFactory.getInstance("X.509")

val CustomParserTests by testSuite {
    val chain: Map<String, JsonObject> by lazy {
        val json = Json { ignoreUnknownKeys = true }
        val classLoader = Thread.currentThread().contextClassLoader

        fun listResourceJsonFiles(resourceDir: String): List<Path> {
            val url = classLoader.getResource(resourceDir)
                ?: error("Missing test resources directory '$resourceDir' on the classpath")

            val uri = url.toURI()
            return when (uri.scheme) {
                "jar" -> FileSystems.newFileSystem(uri, emptyMap<String, Any>()).use { fs ->
                    val root = fs.getPath(resourceDir)
                    Files.list(root).use { stream ->
                        stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".json") }
                            .sorted()
                            .toList()
                    }
                }

                else -> {
                    val root = Paths.get(uri)
                    Files.list(root).use { stream ->
                        stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".json") }
                            .sorted()
                            .toList()
                    }
                }
            }
        }

        val paths = listResourceJsonFiles("attestation-results").also { it.shouldNotBeEmpty() }
        paths.associate { path ->

            val text = Files.readString(path).also { it.shouldNotBeBlank() }
            path.fileName.toString() to json.parseToJsonElement(text).jsonObject
        }
    }

    "fixtures are present" {
        chain.size shouldBeGreaterThan 0
        chain.forEach { (_, json) -> json.isNotEmpty() shouldBe true }
    }

    withData(chain) - {
        val challenge = it.getValue("challenge").jsonPrimitive.content
        val chain = it.getValue("attestationProof").jsonArray.map {
            Base64.getMimeDecoder().decode(it.jsonPrimitive.content.replace("\n", ""))
        }
        val attestationCertChain =
            chain.map { certificateFactory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        val androidAttestationExtension = attestationCertChain.first().androidAttestationExtension

        "convert" - {
            withData(nameFn = {it.subjectX500Principal.toString()}, attestationCertChain) {
                it.toKmpCertificate().isSuccess shouldBe true
                it.toKmpCertificate().getOrThrow().encodeToDer() shouldBe it.encoded
            }
        }
        val fromGoogle = catchingUnwrapped { ParsedAttestationRecord.createParsedAttestationRecord(attestationCertChain)}.getOrNull()
        "From Google" {
            fromGoogle.shouldNotBeNull()
        }
        "Own" {
            val google = fromGoogle.shouldNotBeNull()
            androidAttestationExtension.shouldNotBeNull()
            androidAttestationExtension.encodeToDer() shouldBe
                    (DEROctetString.fromByteArray(
                        attestationCertChain.first().getExtensionValue(
                            AttestationKeyDescription.oid.toString()
                        )
                    ) as ASN1OctetString).octets

            androidAttestationExtension.attestationChallenge shouldBe Base64.getMimeDecoder().decode(challenge)
            assertSemanticallyEqual(google, androidAttestationExtension)

        }
    }
}
