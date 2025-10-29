import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer = System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    id("de.infix.testBalloon") version testballoonVer apply false
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("at.asitplus.gradle.conventions") version "20251023"
    id("com.android.kotlin.multiplatform.library") version "8.12.3" apply (false)
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