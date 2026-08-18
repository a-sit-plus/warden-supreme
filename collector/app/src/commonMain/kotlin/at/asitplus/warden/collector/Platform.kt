package at.asitplus.warden.collector

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform