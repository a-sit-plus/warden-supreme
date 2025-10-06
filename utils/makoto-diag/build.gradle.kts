

plugins {
    kotlin("jvm")
    application
    id("at.asitplus.gradle.conventions")
    id("com.gradleup.shadow")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

application {
    mainClass.set("at.asitplus.attestation.DiagKt")
}

dependencies {
    implementation(project(":makoto"))
}
