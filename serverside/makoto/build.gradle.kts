import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.setupDokka
import org.gradle.kotlin.dsl.kotlin
import java.nio.file.Files
import java.util.Properties

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("at.asitplus.gradle.conventions")
    id("de.infix.testBalloon")
    alias(libs.plugins.sbombastic)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion


sourceSets.test {
    kotlin {
        srcDir("../roboto/src/test/kotlin/data")
    }
}

val generatedSrcDir = "${project.layout.projectDirectory.dir("src")}/generated/kotlin"
sourceSets.main {
    kotlin.srcDir(generatedSrcDir)
}
File(generatedSrcDir).mkdirs()
File("$generatedSrcDir/wardenVersion.kt").writer().apply {

    write(
        """
package at.asitplus.attestation

internal val wardenVersion: String = """" + "$version\"\n")
    close()
}

dependencies {
    api(project(":roboto"))
    api(bouncycastle("bcpkix", "jdk18on"))
    api(datetime())
    api(libs.devicecheck)
    implementation(libs.jackson.cbor)
    implementation(libs.semver)
    implementation(libs.slf4j.api)
    implementation(libs.jackson.kotlin)
    implementation(libs.yamltk)

    testImplementation(libs.slf4j.reload4j)
    testImplementation(kotlin("reflect"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.7.1")
}


setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/serverside",
)
val javadocRedirectJar = tasks.named<Jar>("javadocRedirectJar")

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}


publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            if (this.name != "relocation") {
                artifact(javadocRedirectJar)
                artifact(sourcesJar.get())
            }
            pom {
                name.set("Warden makoto")
                description.set("Server-Side Android+iOS Attestation Library")
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
                        name.set("Bernd Prünster")
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
            }else
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
