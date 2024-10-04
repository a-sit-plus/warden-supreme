import at.asitplus.gradle.ktor
import at.asitplus.gradle.setupDokka

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

group = "at.asitplus.veritatis"
val artifactVersion: String by extra
version = artifactVersion



kotlin {
    jvm()

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain.dependencies {
            api(project(":radix"))
        }

        commonTest.dependencies {
            implementation(ktor("server-netty"))
            implementation(ktor("serialization-kotlinx-json"))
            implementation(ktor("server-content-negotiation"))
            implementation(libs.supreme)

        }

        jvmMain.dependencies{
            api(libs.warden)
        }
    }
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/veritas/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("Sanctor Veritatis")
                description.set("Attestation verifier; part of the VERITAS integrated key attestation suite")
                url.set("https://github.com/a-sit-plus/veritas")
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
                    connection.set("scm:git:git@github.com:a-sit-plus/veritas.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/veritas.git")
                    url.set("https://github.com/a-sit-plus/veritas")
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
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
