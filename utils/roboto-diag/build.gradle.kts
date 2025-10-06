

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
    mainClass.set("at.asitplus.attestation.android.DiagKt")
}

sourceSets.main {
    java {
        srcDirs("${project.rootDir}dependencies/android-key-attestation/src/main/java")

        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java",
        )
        File("${project.rootDir}/dependencies/android-key-attestation/src/main/java/com/google/android/attestation/AuthorizationList.java").let {
            if (it.exists()) {
                it.renameTo(File(it.canonicalPath + ".bak"))
            }
        }
    }
}


dependencies {
    implementation(project(":roboto"))
    implementation(libs.autovalue.annotations)
    implementation(libs.gson)
    implementation(libs.signum) {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }
}
