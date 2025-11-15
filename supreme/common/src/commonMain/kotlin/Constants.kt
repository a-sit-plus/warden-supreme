package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object WardenDefaults {
    @OptIn(ExperimentalUuidApi::class)
    object OIDs {
        val ATTESTATION_PROOF = ObjectIdentifier(Uuid.parse("3fe0e8a9-4a7a-4cd1-a3cc-93c228908116"))
        val DEVICE_NAME = ObjectIdentifier(Uuid.parse("792c51ff-6032-47a3-9c1c-2401be1b6a2f"))
    }
}