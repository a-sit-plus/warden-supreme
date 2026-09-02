plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.conventions")
    id("com.gradleup.shadow")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion


application {
    mainClass.set("at.asitplus.attestation.creator.CreatorKt")
}



dependencies {
    implementation(project(":supreme-common"))
    implementation(libs.signum)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
}
