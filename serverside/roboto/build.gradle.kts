import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.ktor
import at.asitplus.gradle.setupDokka

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("maven-publish")
    id("org.jetbrains.dokka")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

sourceSets.main {
    java {
        srcDirs(
            "${project.rootDir}/dependencies/android-key-attestation/src/main/java",
            "${project.rootDir}/dependencies/keyattestation/src/main/kotlin/"
        )


        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java",
            "testing"
        )
        File("${project.rootDir}/dependencies/android-key-attestation/src/main/java/com/google/android/attestation/AuthorizationList.java").let {
            if (it.exists()) {
                it.delete()
            }
        }
    }
}

sourceSets.test {
    /* cursed workaround for including this very same source directory in another project when using this project
    for composite builds */
    kotlin {
        srcDir("src/test/kotlin/data")
    }
    java {
        srcDirs("${project.rootDir}/dependencies/http-proxy/src/main/java")
    }
    resources {
        srcDirs(
            rootProject.layout.projectDirectory.dir("dependencies").dir("android-key-attestation").dir("src")
                .dir("test")
                .dir("resources"),
            "src/test/resources"
        )
    }
}


dependencies {
    api(bouncycastle("bcpkix", "jdk18on"))
    implementation(ktor("client-core"))
    implementation(ktor("client-content-negotiation"))
    implementation(ktor("serialization-kotlinx-json"))
    implementation(ktor("client-cio"))

    api(libs.guava)
    implementation(libs.autovalue.annotations)
    annotationProcessor(libs.autovalue.value)
    api(libs.signum) {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }


    //dependencies for new attestation lib
    implementation(libs.cbor)
    implementation(libs.gson)
    implementation(libs.errorprone.annotations)
    implementation(libs.protobuf.javalite)
    api(libs.protobuf.kotlinlite)

    testImplementation(libs.slf4j.reload4j)
    testImplementation("io.netty:netty-all:4.1.94.Final")
    testImplementation("commons-cli:commons-cli:1.4")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
    testImplementation("ch.qos.logback:logback-access:1.2.3")
    testImplementation(ktor("client-mock"))
    testImplementation(datetime())
}


tasks.test {
    useJUnitPlatform()
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/",
    multiModuleDoc = true
)

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}


publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            if (this.name != "relocation") {
                artifact(javadocJar.get())
                artifact(sourcesJar.get())
            }
            pom {
                name.set("Warden roboto")
                description.set("Server-Side Android Attestation Library")
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
