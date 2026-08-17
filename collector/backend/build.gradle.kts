import at.asitplus.gradle.datetime
import at.asitplus.gradle.ktor

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    alias(libs.plugins.ktor)
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

application {
    mainClass = "io.ktor.server.cio.EngineMain"
}

dependencies {
    implementation(project(":collector-shared"))
    implementation(project(":supreme-verifier"))
    implementation(datetime())

    implementation(ktor("server-core"))
    implementation(ktor("server-cio"))
    implementation(ktor("server-config-yaml"))
    implementation(ktor("server-content-negotiation"))
    implementation(ktor("serialization-kotlinx-json"))
    implementation(libs.logback.classic)

    testImplementation(kotlin("test"))
    testImplementation(ktor("server-test-host"))
}
