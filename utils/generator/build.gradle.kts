import at.asitplus.gradle.coroutines
import at.asitplus.gradle.serialization
import at.asitplus.gradle.setupDokka

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.conventions")
    id("com.gradleup.shadow")
    alias(libs.plugins.sbombastic)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion


java {
    withSourcesJar()
}

application {
    mainClass.set("at.asitplus.attestation.generator.GeneratorKt")
}

dependencies {
    // The DSL hands out parser types, certificates and signers, so both are part of the API.
    api(project(":supreme-common"))
    api(libs.signum)
    implementation(coroutines())
    implementation(serialization("json"))
}

setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/utils",
)
val javadocRedirectJar = tasks.named<Jar>("javadocRedirectJar")

/**
 * Only the plain library jar is published; the shaded CLI jar ships with the documentation instead.
 * The Shadow plugin adds its own variant to the `java` component, which has to be skipped explicitly.
 */
afterEvaluate {
    components.named<AdhocComponentWithVariants>("java") {
        withVariantsFromConfiguration(configurations["shadowRuntimeElements"]) { skip() }
    }
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(javadocRedirectJar)
            pom { describeGenerator() }
        }
        withType<MavenPublication> {
            if (this.name != "relocation" && this.name != "mavenJava") artifact(javadocRedirectJar)
            pom { describeGenerator() }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(rootProject.layout.projectDirectory.dir("repo"))
            this.name = "local"
            if (System.getenv("SIGN_LOCAL_REPO_ARTEFACTS")?.ifBlank { "false" } != "true") {
                logger.lifecycle("  > NOT signing locally published maven artefacts!")
                signing {
                    isRequired = false
                }
            } else
                logger.lifecycle("  > Signing locally published maven artefacts!")
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}

fun org.gradle.api.publish.maven.MavenPom.describeGenerator() {
    name.set("Warden Attestation Generator")
    description.set("Generates fake Android key attestation statements and certificate chains for testing")
    url.set("https://github.com/a-sit-plus/warden-supreme")
    licenses {
        license {
            name.set("The Apache License, Version 2.0")
            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
        }
    }
    developers {
        developer {
            id.set("JesusMcCloud")
            name.set("Bernd Pruenster")
            email.set("bernd.pruenster@a-sit.at")
        }
        developer {
            id.set("nodh")
            name.set("Christian Kollmann")
            email.set("christian.kollmann@a-sit.at")
        }
    }
    scm {
        connection.set("scm:git:git@github.com:a-sit-plus/warden-supreme.git")
        developerConnection.set("scm:git:git@github.com:a-sit-plus/warden-supreme.git")
        url.set("https://github.com/a-sit-plus/warden-supreme")
    }
}
