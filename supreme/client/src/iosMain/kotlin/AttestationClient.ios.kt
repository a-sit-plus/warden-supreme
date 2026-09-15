package at.asitplus.attestation.supreme

import kotlinx.cinterop.*
import platform.posix.uname
import platform.posix.utsname

@OptIn(ExperimentalForeignApi::class)
actual fun getDeviceName(): String = memScoped {
    val systemInfo = alloc<utsname>()
    if (uname(systemInfo.ptr) != 0) {
        return "iPhone"
    }
    // e.g. "iPhone15,3"
    systemInfo.machine.toKString()
}
