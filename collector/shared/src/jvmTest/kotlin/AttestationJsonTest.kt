import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.warden.collector.shared.toReadableJson
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AttestationJsonTest {

    @Test
    fun rendersAuthorizationListReadably() {
        val list = AuthorizationList(
            purpose = setOf(AuthorizationList.KeyPurpose.SIGN, AuthorizationList.KeyPurpose.VERIFY),
            algorithm = AuthorizationList.Algorithm.EC,
            ecCurve = AuthorizationList.ECCurve.P_256,
            origin = AuthorizationList.Origin.GENERATED,
            noAuthRequired = AuthorizationList.NoAuthRequired,
            rootOfTrust = AuthorizationList.RootOfTrust(
                verifiedBootKeyDigest = ByteArray(4) { 0x0a },
                deviceLocked = true,
                verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
                verifiedBootHash = null,
            ),
        )

        val json = list.toReadableJson()

        assertEquals("EC", json["algorithm"]!!.jsonPrimitive.content)
        assertEquals("P_256", json["ecCurve"]!!.jsonPrimitive.content)
        assertEquals("GENERATED", json["origin"]!!.jsonPrimitive.content)
        assertEquals(
            setOf("SIGN", "VERIFY"),
            json["purpose"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet(),
        )
        assertTrue(json["noAuthRequired"]!!.jsonPrimitive.boolean)

        // Absent tags are omitted entirely.
        assertTrue("keySize" !in json)

        // Nested structure renders as an object with decoded fields.
        val rot = json["rootOfTrust"]!!
        assertTrue(rot.toString().contains("Verified"))
    }
}
