import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.setupDokka
import org.gradle.kotlin.dsl.kotlin
import org.gradle.kotlin.dsl.support.listFilesOrdered

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("at.asitplus.gradle.conventions")
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

dependencies {
    api(project(":roboto"))
    api(bouncycastle("bcpkix", "jdk18on"))
    api(datetime())
    api(libs.devicecheck)
    implementation(libs.jackson.cbor)
    implementation(libs.semver)
    implementation(libs.slf4j.api)
    implementation(libs.jackson.kotlin)

    testImplementation(libs.slf4j.reload4j)
    testImplementation(kotlin("reflect"))
}


val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            if (this.name != "relocation") artifact(javadocJar.get())
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
    }
}



signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
