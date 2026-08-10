import at.asitplus.gradle.ktor
import at.asitplus.gradle.setupDokka


plugins {
    id("com.android.kotlin.multiplatform.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.conventions")
    alias(libs.plugins.sbombastic)
}


val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

kotlin {
    iosArm64()
    iosSimulatorArm64()
    android {
        namespace = "at.asitplus.attestation.supreme.client"
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunnerArguments["timeout_msec"] = "2400000"
            managedDevices {
                localDevices {
                    create("pixelAVD").apply {
                        device = "Pixel 4"
                        apiLevel = 30
                        systemImageSource = "aosp"
                    }
                }
            }
        }


        packaging {
            resources.excludes.add("/META-INF/{AL2.0,LGPL2.1}")
            resources.excludes.add("win32-x86-64/attach_hotspot_windows.dll")
            resources.excludes.add("win32-x86/attach_hotspot_windows.dll")
            resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
            resources.excludes.add("META-INF/licenses/*")
        }
    }




    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain.dependencies {
            api(project(":supreme-common"))
            implementation(ktor("client-core"))
            api(ktor("client-content-negotiation"))
            api(ktor("client-encoding"))
            api(ktor("serialization-kotlinx-json"))
            api(libs.supreme)
        }

        getByName("androidDeviceTest").dependencies {
            implementation(ktor("client-cio"))
            implementation(ktor("serialization-kotlinx-json"))
            implementation(ktor("client-content-negotiation"))
        }

        commonTest.dependencies {
            implementation(ktor("client-mock"))
            implementation("at.asitplus.gradle:testhelper:20251114")
            implementation(ktor("client-mock"))
        }
    }
}


//The new KMP android library plugin is just the worst!
val ksPath = layout.projectDirectory.file("keystore.p12").asFile.absolutePath
val ksPass = "123456"
val keyAlias = "key0"
val keyPass = "123456"
val ksType = "PKCS12" // important for .p12

// Helper to locate apksigner (falls back to PATH if not found via ANDROID_SDK_ROOT)
fun findApkSigner(): String {
    val sdkRoot = providers.environmentVariable("ANDROID_SDK_ROOT").orNull
        ?: providers.environmentVariable("ANDROID_HOME").orNull ?: project.extra.get("sdk.dir")
    if (sdkRoot != null) {
        val buildTools = File("$sdkRoot/build-tools")
        val latest = buildTools.listFiles()?.maxByOrNull { it.name } // pick highest version
        val exe = File(latest, "apksigner")
        if (exe.exists()) return exe.absolutePath
    }
    return "apksigner"
}

val resignTestApk = tasks.register("resignTestApk") {
    // make sure the APK exists first
    dependsOn("packageAndroidDeviceTest")

    doLast {
        val outDir = layout.buildDirectory.dir("outputs/apk/androidTest").get().asFile
        val apks = fileTree(outDir) { include("**/*.apk") }.files.toList()
        require(apks.isNotEmpty()) {
            "No androidDeviceTest APKs found under: $outDir"
        }

        val apksigner = findApkSigner()

        apks.forEach { apk ->
            // Re-sign IN PLACE so downstream install tasks pick up the fixed cert
            val process = ProcessBuilder(
                apksigner, "sign",
                "--ks", ksPath,
                "--ks-pass", "pass:$ksPass",
                "--ks-key-alias", keyAlias,
                "--key-pass", "pass:$keyPass",
                "--ks-type", ksType,
                apk.absolutePath
            ).inheritIO().start()

            val exitCode = process.waitFor()

            if (exitCode != 0) {
                throw GradleException("apksigner failed with exit code $exitCode")
            }

            println("Re-signed ${apk.name} device-test APK with $keyAlias from $ksPath")}

    }
}
// Instead of whenObjectAdded, use the newer Task Configuration Avoidance API
tasks.matching { it.name == "createAndroidDeviceTestApkListingFileRedirect" }.configureEach {
    dependsOn(resignTestApk)
}

// If there is an installation task, ensure it runs AFTER the signing
tasks.matching { it.name.contains("installAndroidDeviceTest") }.configureEach {
    mustRunAfter(resignTestApk)
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/supreme",
)

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("Warden Supreme Client")
                description.set("Attestation mobile client; part of the WARDEN Supreme integrated key attestation suite")
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
