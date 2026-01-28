plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer =
        System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    id("de.infix.testBalloon") version testballoonVer apply false
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    alias(libs.plugins.asp)
    alias(libs.plugins.agp) apply (false)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion


val dokkaDir = rootProject.layout.buildDirectory.dir("dokka")
dokka {
    dokkaPublications.html {
        outputDirectory.set(dokkaDir)
    }
    // moduleName.set("Warden Supreme")
}

subprojects {
    rootProject.dependencies.add("dokka", this)
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
    dependsOn("dokkaGenerate")
    dependsOn("copyChangelog")
    dependsOn(project(":supreme-common").tasks.named<Test>("jvmTest") {
        setTestNameIncludePatterns(listOf("examples.*"))
    }) //to generate JSON schema
    dependsOn(project(":supreme-verifier").tasks.named<Test>("jvmTest") {
        setTestNameIncludePatterns(listOf("examples.*"))
    }) //to generate config files
    into(rootDir.resolve("docs/docs/dokka"))
    from(dokkaDir)
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    workingDir("${rootDir}/docs")
    commandLine("mkdocs", "build", "--clean", "--strict")
}

tasks.register<Copy>("mkDocsSite") {
    dependsOn("mkDocsBuild")
    into(rootDir.resolve("docs/site/assets/images/social"))
    from(rootDir.resolve("docs/docs/assets/images/social"))
}