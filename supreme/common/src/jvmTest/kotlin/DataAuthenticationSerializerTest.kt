import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import net.mamoe.yamlkt.Yaml

val DataAuthenticationSerializerTest by matrixSuite {
    data(
        "concrete Hash serializer",
        listOf(Digest.SHA256, Digest.SHA384, Digest.SHA512),
    ) test { digest ->
        val value = DataAuthentication.Hash(digest)
        val serializer = DataAuthentication.Hash.serializer()
        val expectedJson = "{\"type\":\"HASH\",\"algorithm\":\"${digest.name}\"}"

        Json.encodeToString(serializer, value) shouldBe expectedJson
        Json.decodeFromString(serializer, expectedJson) shouldBe value
        val yaml = Yaml.encodeToString(serializer, value)
        Yaml.decodeFromString(serializer, yaml) shouldBe value
    }

    data(
        "variants",
        listOf(
            DataAuthentication.Signature to "{\"type\":\"SIGNATURE\"}",
            DataAuthentication.Hash(Digest.SHA256) to "{\"type\":\"HASH\",\"algorithm\":\"SHA256\"}",
        ),
        nameFn = { _, (value) -> value::class.simpleName!! },
    ) test { (value, expectedJson) ->
        Json.encodeToString(DataAuthentication.serializer(), value) shouldBe expectedJson
        Json.decodeFromString(DataAuthentication.serializer(), expectedJson) shouldBe value

        val yaml = Yaml.encodeToString(DataAuthentication.serializer(), value)
        Yaml.decodeFromString(DataAuthentication.serializer(), yaml) shouldBe value
    }

    test("rejects SHA-1") {
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<DataAuthentication>(
                "{\"type\":\"HASH\",\"algorithm\":\"SHA1\"}",
            )
        }.message shouldBe "SHA-1 is insecure"
    }

    test("format-level unknown-key handling remains intact") {

        val lenientJson = Json { ignoreUnknownKeys = true }
        lenientJson.decodeFromString<DataAuthentication>(
            "{\"type\":\"HASH\",\"algorithm\":\"SHA256\",\"futureOption\":true}",
        ) shouldBe DataAuthentication.Hash(Digest.SHA256)
    }
}
