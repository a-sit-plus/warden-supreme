import at.asitplus.gradle.datetime
import at.asitplus.gradle.ktor
import org.gradle.language.jvm.tasks.ProcessResources

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

val collectorVersionCode = providers.gradleProperty("collector.versionCode")
val generatedCollectorVersion = layout.buildDirectory.file("generated/collector-resources/collector-version.txt")
val generateCollectorVersion = tasks.register("generateCollectorVersion") {
    inputs.property("collectorVersionCode", collectorVersionCode)
    outputs.file(generatedCollectorVersion)
    doLast {
        generatedCollectorVersion.get().asFile.apply {
            parentFile.mkdirs()
            writeText(collectorVersionCode.get())
        }
    }
}

dependencies {
    implementation(project(":collector-shared"))
    implementation(project(":supreme-verifier"))
    implementation(datetime())

    implementation(ktor("server-core"))
    implementation(ktor("server-cio"))
    implementation(ktor("server-config-yaml"))
    implementation(ktor("server-content-negotiation"))
    implementation(ktor("server-html-builder"))
    implementation(ktor("serialization-kotlinx-json"))
    implementation(libs.logback.classic)

    testImplementation(kotlin("test"))
    testImplementation(ktor("server-test-host"))
}

sourceSets.main {
    resources.exclude("collector-version.txt", "collector-android-release.apk")
}

tasks.named<ProcessResources>("processResources") {
    dependsOn(":collector-android:assembleRelease", generateCollectorVersion)
    from(project(":collector-android").layout.buildDirectory.file("outputs/apk/release/collector-android-release.apk")) {
        rename { "collector.apk" }
    }
    from(generatedCollectorVersion)
}
