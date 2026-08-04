import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.AttestedAttributes
import at.asitplus.attestation.supreme.Primitive
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.toSequence
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val AttestedAttributesTest by matrixSuite {
    "optional attributes may be absent" {
        val requested = listOf(
            AttestationChallenge.ToBeAttestedAttribute("required", PrimitiveType.STRING),
            AttestationChallenge.ToBeAttestedAttribute("optional", PrimitiveType.INT, required = false),
        )

        AttestedAttributes(listOf<Primitive>("value", null).toSequence())
            .parsedAttributesBy(requested) shouldBe listOf("value", null)
    }

    "required attributes may not be absent" {
        val requested = listOf(
            AttestationChallenge.ToBeAttestedAttribute("required", PrimitiveType.STRING),
        )

        shouldThrow<IllegalArgumentException> {
            AttestedAttributes(
                listOf<Primitive>(null).toSequence(),
            ).parsedAttributesBy(requested)
        }
    }

    "requested attribute sequence must be present" {
        shouldThrow<IllegalArgumentException> {
            AttestedAttributes(null).parsedAttributesBy(
                listOf(AttestationChallenge.ToBeAttestedAttribute("required", PrimitiveType.STRING))
            )
        }
    }

    "unrequested attribute sequence is rejected" {
        shouldThrow<IllegalArgumentException> {
            AttestedAttributes(
                listOf<Primitive>("unexpected").toSequence(),
            ).parsedAttributesBy(null)
        }
    }
}
