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
    mainClass.set("at.asitplus.attestation.DiagKt")
}

dependencies {
    implementation(project(":makoto"))
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
