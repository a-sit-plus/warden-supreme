import at.asitplus.gradle.setupDokka

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.conventions")
    alias(libs.plugins.sbombastic)
    alias(libs.plugins.pitest)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

java {
    withSourcesJar()
}

dependencies {
    api(project(":supreme-common"))
    compileOnly(libs.spring.boot)

    testImplementation(project(":supreme-verifier"))
    testImplementation(libs.spring.boot.autoconfigure)
    testImplementation(libs.spring.boot.starter)
    testImplementation(libs.spring.boot.starter.test)
}

tasks.test {
    useJUnitPlatform()
}

pitest {
    junit5PluginVersion.set(libs.versions.pitest.junit5.get())
    pitestVersion.set("1.18.2")
    targetClasses.set(listOf("at.asitplus.attestation.ConfigurationSpring*"))
    targetTests.set(listOf("at.asitplus.attestation.SpringPitestBridgeTest"))
    mutationThreshold.set(100)
    coverageThreshold.set(100)
    testStrengthThreshold.set(100)
    outputFormats.set(listOf("HTML", "XML"))
    timestampedReports.set(false)
    threads.set(1)
    verbose.set(false)
}

setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/supreme",
)
val javadocRedirectJar = tasks.named<Jar>("javadocRedirectJar")

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(javadocRedirectJar)
            pom {
                name.set("Warden Config Spring")
                description.set("Spring Boot integration helpers for Warden Supreme configuration")
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
        }
        withType<MavenPublication> {
            if (this.name != "relocation" && this.name != "mavenJava") artifact(javadocRedirectJar)
            pom {
                name.set("Warden Config Spring")
                description.set("Spring Boot integration helpers for Warden Supreme configuration")
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
