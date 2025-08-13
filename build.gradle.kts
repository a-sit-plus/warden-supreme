import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    val kotlinVer =
        System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer =
        System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer = System.getenv("KSP_VERSION_ENV")?.ifBlank { null }
        ?: "$kotlinVer-${libs.versions.ksp.get()}"

    id("at.asitplus.gradle.conventions") version "20250729"
    id("io.kotest") version kotestVer
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.google.devtools.ksp") version kspVer
    id("com.android.library") version "8.10.0" apply (false)
}

group = "at.asitplus.wardensupreme"


//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("$buildDir/dokka"))
    includes.from("README.md")
    moduleName.set("WARDEN Supreme")
}

allprojects {
    repositories {
        mavenLocal()
    }
}