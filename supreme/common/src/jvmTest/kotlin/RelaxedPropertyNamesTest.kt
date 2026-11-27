import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.attestation.withRelaxedPropertyNames
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

private fun yamlForm(type: String, vararg properties: Pair<String, String>) = buildJsonObject {
    putJsonObject("algorithmParameters") {
        put("type", type)
        putJsonObject("value") { properties.forEach { (k, v) -> put(k, v) } }
    }
}

private fun JsonElement.decodeKeyConstraints() =
    Json.decodeFromJsonElement(KeyConstraints.serializer(), withRelaxedPropertyNames(KeyConstraints.serializer()))

val RelaxedPropertyNamesTest by matrixSuite {
    // yamlkt encodes sealed classes as `{type, value: {...}}`; Hoplite hands that shape over as-is.
    test("sealed values in yamlkt form are flattened, so non-default properties survive") {
        yamlForm("EC", "curve" to "P-384", "allowKeyAgreement" to "true").decodeKeyConstraints() shouldBe
                KeyConstraints(KeyConstraints.AlgorithmParameters.EC(ECCurve.SECP_384_R_1, allowKeyAgreement = true))

        yamlForm("RSA", "keySize" to "4096", "allowDecrypting" to "true").decodeKeyConstraints() shouldBe
                KeyConstraints(KeyConstraints.AlgorithmParameters.RSA(BitLength(4096u), allowDecrypting = true))
    }

    test("relaxed property names still apply inside the flattened value") {
        yamlForm("RSA", "key-size" to "2048").decodeKeyConstraints() shouldBe
                KeyConstraints(KeyConstraints.AlgorithmParameters.RSA(BitLength(2048u)))
    }

    test("flat sealed values are unchanged") {
        val flat = Json.encodeToJsonElement(
            KeyConstraints.serializer(),
            KeyConstraints(KeyConstraints.AlgorithmParameters.EC(ECCurve.SECP_521_R_1))
        )
        flat.withRelaxedPropertyNames(KeyConstraints.serializer()) shouldBe flat
    }

    test("type/value pairs outside sealed hierarchies are left alone") {
        val map = buildJsonObject {
            putJsonObject("entry") {
                put("type", "x")
                putJsonObject("value") { put("a", "1") }
            }
        }
        map.withRelaxedPropertyNames(MapSerializer(String.serializer(), JsonObject.serializer())) shouldBe map
    }

    test("a nested discriminator inside value is not flattened") {
        val nested = buildJsonObject {
            put("type", JsonPrimitive("EC"))
            putJsonObject("value") { put("type", "RSA") }
        }
        val wrapped = buildJsonObject { put("algorithmParameters", nested) }
        (wrapped.withRelaxedPropertyNames(KeyConstraints.serializer()) as JsonObject)["algorithmParameters"] shouldBe nested
    }
}
