import at.asitplus.gradle.ktor
import at.asitplus.gradle.setupDokka
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread


plugins {
    id("com.android.library")
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
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(test)
    }

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain.dependencies {
            api(project(":radix"))
            implementation(ktor("client-core"))
            api(ktor("client-content-negotiation"))
            api(ktor("client-encoding"))
            api(ktor("serialization-kotlinx-json"))
            api(libs.supreme)
        }
    }
}


android {
    namespace = "at.asitplus.veritatis.servus"
    compileSdk = 34
    defaultConfig {
        minSdk = 30
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    testBuildType = "debug"

    //just for instrumented tests
    signingConfigs {
        getByName("debug") {
            storeFile = file("keystore.p12")
            storePassword = "123456"
            keyAlias = "key0"
            keyPassword = "123456"
        }
        create("release") {
            storeFile = file("keystore.p12")
            storePassword = "123456"
            keyAlias = "key0"
            keyPassword = "123456"
        }
    }

    sourceSets.forEach {

        //allow plain traffic and set permissions
        if (it.name.lowercase().contains("test") || name.lowercase().contains("debug"))
            it.manifest.srcFile("src/androidInstrumentedTest/AndroidManifest.xml")
    }

    dependencies {
        androidTestImplementation(libs.runner)
        androidTestImplementation(libs.core)
        androidTestImplementation(libs.rules)
        androidTestImplementation(libs.kotest.runner.android)
        androidTestImplementation(ktor("client-cio"))
        androidTestImplementation(ktor("serialization-kotlinx-json"))
        androidTestImplementation(ktor("client-content-negotiation"))
        testImplementation(libs.kotest.extensions.android)
    }

    packaging {
        resources.excludes.add("/META-INF/{AL2.0,LGPL2.1}")
        resources.excludes.add("win32-x86-64/attach_hotspot_windows.dll")
        resources.excludes.add("win32-x86/attach_hotspot_windows.dll")
        resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
        resources.excludes.add("META-INF/licenses/*")
    }

    testOptions {
        targetSdk=30
        managedDevices {
            localDevices {
                create("pixel2api33") {
                    device = "Pixel 2"
                    apiLevel = 30
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}


val startSanctor = tasks.register<DefaultTask>("startSanctor") {
    doLast {
        if (!kotlin.runCatching { Socket("localhost", 8080) }.fold(onSuccess = { true }, onFailure = { false }))
            logger.lifecycle("Starting Sanctor")
        else {
            logger.lifecycle("Shutting down Sanctor")
            runCatching {
                HttpClients.createDefault().let { client ->
                  logger.lifecycle("Sanctor response: ${client.execute(HttpGet("http://localhost:8080/shutdown")).statusLine.statusCode}")
                }
            }.getOrElse { logger.lifecycle("Sanctor not running"); it.printStackTrace()  }

        }
       thread(start = true, isDaemon = false) {
            exec {
                workingDir = rootDir
                executable = "./gradlew"
                args = listOf(":sanctor:jvmTest")
            }
        }

        logger.lifecycle("Waiting for Sanctor to start")
        while (kotlin.runCatching { Socket("localhost", 8080) }.fold(onSuccess = { true }, onFailure = { false })) {
            Thread.sleep(1000)
            logger.lifecycle("Waiting for Sanctor to start")
        }
        logger.lifecycle("Sanctor started")
    }
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/veritas/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("Servus Veritatis")
                description.set("Attestation client; part of the VERITAS integrated key attestation suite")
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
