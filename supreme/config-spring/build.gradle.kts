import at.asitplus.gradle.setupDokka

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

dependencies {
    api(project(":supreme-common"))
    compileOnly(libs.spring.boot)

    testImplementation(project(":supreme-verifier"))
    testImplementation(libs.spring.boot.autoconfigure)
    testImplementation(libs.spring.boot.starter)
    testImplementation(libs.spring.boot.starter.test)
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/supreme",
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
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
