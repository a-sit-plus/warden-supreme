import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer = System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer = System.getenv("KSP_VERSION_ENV")?.ifBlank { null } ?: "$kotlinVer-${libs.versions.ksp.get()}"
    id("io.kotest") version kotestVer apply false //we need the plugin in the classpath until I clean up the conventions plugins
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("at.asitplus.gradle.conventions") version "20250729"
    id("com.google.devtools.ksp") version kspVer
    id("com.android.library") version "8.10.0" apply (false)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("${rootDir}/dokka"))
    moduleName.set("Warden Supreme")
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}


tasks.register<Copy>("copyChangelog") {
    into(rootDir.resolve("docs/docs"))
    from("CHANGELOG.md")
}

tasks.register<Copy>("mkDocsPrepare") {
    dependsOn("dokkaHtmlMultiModule")
    dependsOn("copyChangelog")
    into(rootDir.resolve("docs/docs/dokka"))
    from("${rootDir}/dokka")
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    workingDir("${rootDir}/docs")
    commandLine("mkdocs", "build", "--clean", "--strict")
}