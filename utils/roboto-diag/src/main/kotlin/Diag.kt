package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import com.google.android.attestation.ParsedAttestationRecord
import com.google.gson.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.interfaces.ECPublicKey

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())
    if (args.isEmpty()) {
        System.err.println("Certificate neither specified in a file (-f <path to PEM/Base64 cert>) nor as parameter <Base64 cert>!")
        System.exit(1)
    }
    val certB64 = if (args[0] == "-f") java.io.File(args[1]).readText() else args[0]

    val full = args.last() == "-v"


    @OptIn(ExperimentalStdlibApi::class, kotlin.io.encoding.ExperimentalEncodingApi::class)
    val gson: Gson = GsonBuilder().apply {

        registerTypeAdapter(
            ByteArray::class.java,
            JsonSerializer<ByteArray> { src, _, _ ->
                JsonPrimitive(src?.toHexString(HexFormat.UpperCase))
            })
        registerTypeAdapter(
            java.time.YearMonth::class.java,
            JsonSerializer<java.time.YearMonth> { src, _, _ ->
                JsonPrimitive(src?.toString())
            })
        registerTypeAdapter(
            java.time.LocalDate::class.java,
            JsonSerializer<java.time.LocalDate> { src, _, _ ->
                JsonPrimitive(src?.toString())
            })
        registerTypeHierarchyAdapter(ECPublicKey::class.java, JsonSerializer<ECPublicKey> { src, _, _ ->
            com.google.gson.JsonObject().apply {
                add("algorithm", JsonPrimitive(src.algorithm))
                add("format", JsonPrimitive(src.format))
                add("encoded", JsonPrimitive(src.encoded.toHexString(HexFormat.UpperCase)))
            }
        })
        registerTypeAdapter(
            java.util.Optional::class.java,
            JsonSerializer<java.util.Optional<*>> { src, _, ctx ->
                catchingUnwrapped {
                    if (src == null || src.isEmpty) {
                        if (!full) null else JsonNull.INSTANCE
                    } else ctx.serialize(src.get())
                }.getOrElse {
                    ctx.serialize(it.message)
                }
            })
        registerTypeAdapter(
            java.security.cert.Certificate::class.java,
            JsonSerializer<java.security.cert.Certificate> { src, _, _ ->
                JsonPrimitive(src?.let { kotlin.io.encoding.Base64.encode(it.encoded) })
            })
        registerTypeAdapter(java.time.Instant::class.java, JsonSerializer<java.time.Instant> { src, _, _ ->
            JsonPrimitive(src?.toString())
        })
        if (!full) registerTypeAdapter(
            com.google.common.collect.ImmutableSet::class.java,
            JsonSerializer<com.google.common.collect.ImmutableSet<*>> { src, _, ctx ->
                if (src == null || src.isEmpty()) null
                else ctx.serialize(src)
            })

        disableJdkUnsafe()
        if (full) serializeNulls()
        setPrettyPrinting()
    }.create()


    println(
        gson.toJson(
            ParsedAttestationRecord.createParsedAttestationRecord(
                listOf(
                    at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromByteArray(certB64.encodeToByteArray())!!
                        .toJcaCertificateBlocking().getOrThrow()
                )
            )
        )
    )
}
