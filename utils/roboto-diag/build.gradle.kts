
import org.gradle.api.publish.PublishingExtension


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
    implementation(project(":supreme-common"))
    implementation(libs.signum) {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }
}

afterEvaluate {
    extensions.findByType(PublishingExtension::class.java)?.let { publishing ->
        listOf("version", "versions").forEach { publicationName ->
            publishing.publications.findByName(publicationName)?.let(publishing.publications::remove)
        }
    }

    tasks.matching { task ->
        task.name.contains("VersionsPublication") ||
            task.name == "checkPomFileForVersionsPublication"
    }.configureEach {
        enabled = false
    }
}
