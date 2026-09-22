package at.asitplus.attestation.supreme

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

val AttestedAttributesBridgeTest by matrixSuite {
    val requested = listOf(
        AttestationChallenge.AttributeAttestationDescriptor("accountId", PrimitiveType.STRING),
        AttestationChallenge.AttributeAttestationDescriptor("riskScore", PrimitiveType.INT, required = false),
    )
    val provided = listOf(
        KotlinAttestedAttributeValue("STRING", false, "account-123", 0, 0.0, null),
        KotlinAttestedAttributeValue("MISSING", false, null, 0, 0.0, null),
    )

    fun resolveProvided() = resolveAttestedAttributes(requested) { provided }

    "resolving attested attributes" - {
        "passes descriptors to the provider in request order" {
            var descriptors = emptyList<KotlinAttestedAttributeDescriptor>()

            resolveAttestedAttributes(requested) {
                descriptors = it
                provided
            }

            descriptors.map { it.name } shouldBe listOf("accountId", "riskScore")
        }

        "maps a provided value" {
            resolveProvided()[0] shouldBe "account-123"
        }

        "preserves a missing optional value" {
            resolveProvided()[1].shouldBeNull()
        }

        "rejects a missing required value" {
            shouldThrow<IllegalArgumentException> {
                resolveAttestedAttributes(requested) {
                    List(2) { KotlinAttestedAttributeValue("MISSING", false, null, 0, 0.0, null) }
                }
            }
        }
    }
}
