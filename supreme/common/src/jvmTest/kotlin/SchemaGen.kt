import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.InstantLongSerializer
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECCurveSerializer
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.github.smiley4.schemakenerator.core.data.InitialKTypeData
import io.github.smiley4.schemakenerator.core.data.TypeData
import io.github.smiley4.schemakenerator.core.data.TypeId
import io.github.smiley4.schemakenerator.jsonschema.JsonSchemaSteps.compileInlining
import io.github.smiley4.schemakenerator.jsonschema.JsonSchemaSteps.generateJsonSchema
import io.github.smiley4.schemakenerator.jsonschema.JsonSchemaSteps.withTitle
import io.github.smiley4.schemakenerator.serialization.SerializationSteps.addJsonClassDiscriminatorProperty
import io.github.smiley4.schemakenerator.serialization.SerializationSteps.analyzeTypeUsingKotlinxSerialization
import java.io.File
import kotlin.reflect.full.createType

        private val pathname = "../../docs/docs/schemas"
val SchemaGeneration by testSuite {

    withData(AttestationChallenge::class, AttestationResponse::class, Attestation::class) {
        val jsonSchema = InitialKTypeData(it.createType(), associatedTypes = listOf())
            // Analyze the type using reflection and extract information
            .analyzeTypeUsingKotlinxSerialization()
            .addJsonClassDiscriminatorProperty()
            // Generate (independent) json schemas for each associated type (here: `MyExampleClass`, `Int`, `Boolean` and `List<Boolean>`)
            .generateJsonSchema()
            .withTitle(::buildMinimal)
            // Combine the individual schemas into a single schema for `MyExampleClass` by inlining all referenced types.
            .compileInlining()


        File(pathname).mkdirs()
        with(File("$pathname/${it.simpleName}.json").writer()) {
            write(jsonSchema.json.prettyPrint())
            close()
        }
    }
}

private fun buildMinimal(type: TypeData, types: Map<TypeId, TypeData>): String {


    val shortName = type.descriptiveName.short
    val typeName =
        if (shortName == InstantLongSerializer::class.simpleName) "Milliseconds since epoch"
        else if (shortName.contains("EllipticCurve")) "EC name. One of: ${ECCurve.entries.joinToString { it.jwkName }}"
        else if (shortName.contains("DigestNamer")) "Digest name. One of: ${Digest.entries.joinToString { it.name }}"
        else if (shortName.lowercase().endsWith("serializer")) shortName.dropLast("serializer".length)
        else shortName
    return buildString {
        append(typeName)
        if (type.typeParameters.isNotEmpty()) {
            append("<")
            append(type.typeParameters.joinToString(",") { buildMinimal(types[it.type]!!, types) })
            append(">")
        }
    }
}