package at.asitplus.attestation.android

interface PrettyPrintable {
    fun doPrettyPrint(indent: String): String
}

fun PrettyPrintable.prettyPrint(): String = doPrettyPrint("  ").trimIndent()