import at.asitplus.gradle.*
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.kotlin.multiplatform.library")
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


// CryptoKit ML-DSA shim: CryptoKit is Swift-only, so a small @objc Swift library is compiled per SDK and consumed via
// cinterop (pattern from Signum's cinterop/AESwift). The static library is embedded into this module's klib.
val mlDsaSwiftSource = file("cinterop/MlDsaSwift/MlDsaSwift.swift")
fun mlDsaSwiftOutput(sdk: String) = layout.buildDirectory.dir("mldsa-swift/$sdk")
val mlDsaSwiftTasks = mapOf(
    "iphoneos" to "arm64-apple-ios15.0",
    "iphonesimulator" to "arm64-apple-ios15.0-simulator",
).mapValues { (sdk, triple) ->
    tasks.register<Exec>("buildMlDsaSwift${sdk.replaceFirstChar { it.titlecase() }}") {
        group = "build"
        description = "Compiles the CryptoKit ML-DSA shim for $sdk"
        val out = mlDsaSwiftOutput(sdk)
        inputs.file(mlDsaSwiftSource)
        outputs.dir(out)
        onlyIf { HostManager.hostIsMac }
        doFirst { out.get().dir("include/MlDsaSwift").asFile.mkdirs() }
        commandLine(
            "xcrun", "--sdk", sdk, "swiftc",
            "-parse-as-library", "-emit-library", "-static",
            "-module-name", "MlDsaSwift",
            "-target", triple,
            "-O", "-whole-module-optimization",
            "-emit-objc-header",
            "-emit-objc-header-path", out.get().file("include/MlDsaSwift/MlDsaSwift-Swift.h").asFile.absolutePath,
            "-o", out.get().file("libMlDsaSwift.a").asFile.absolutePath,
            mlDsaSwiftSource.absolutePath,
        )
    }
}

// The iOS simulator grants keychain access only to binaries carrying these entitlements in their
// `__TEXT,__entitlements` section (as Signum does for its own simulator tests). Without them, the Keychain-backed
// ML-DSA tests fail with errSecNotAvailable / errSecMissingEntitlement.
val iosTestAppIdentifier = "at.asitplus.warden.supreme.common.test"
val iosTestEntitlementsFile = layout.buildDirectory.file("tmp/iosSimTest.entitlements").get().asFile.apply {
    parentFile.mkdirs()
    writeText(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>application-identifier</key>
            <string>$iosTestAppIdentifier</string>
            <key>keychain-access-groups</key>
            <array>
                <string>$iosTestAppIdentifier</string>
            </array>
        </dict>
        </plist>
        """.trimIndent()
    )
}

kotlin {
    jvm()
    val iosTargets = listOf(iosArm64(), iosSimulatorArm64())
    if (HostManager.hostIsMac) iosTargets.forEach { target ->
        val sdk = if (target.name == "iosArm64") "iphoneos" else "iphonesimulator"
        val swiftTask = mlDsaSwiftTasks.getValue(sdk)
        val out = mlDsaSwiftOutput(sdk).get().asFile
        target.compilations.getByName("main").cinterops.create("MlDsaSwift") {
            definitionFile.set(file("cinterop/MlDsaSwift-$sdk.def"))
            includeDirs(out.resolve("include"))
            extraOpts("-libraryPath", out.absolutePath)
            tasks.named(interopProcessingTaskName) { dependsOn(swiftTask) }
        }
        if (sdk == "iphonesimulator") {
            target.binaries.getTest(org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType.DEBUG)
                .linkerOpts("-sectcreate", "__TEXT", "__entitlements", iosTestEntitlementsFile.absolutePath)
        }
    }
    android {
        namespace = "at.asitplus.warden.supreme.common"
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunnerArguments["timeout_msec"] = "2400000"
            managedDevices {
                localDevices {
                    create("pixelAVD").apply {
                        device = "Pixel 4"
                        apiLevel = 30
                        systemImageSource = "aosp-atd"
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
            resources.excludes.add("META-INF/LICENSE.md")
        }

    }

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain.dependencies {
            api(libs.signum)
            api(libs.supreme)
            api(serialization("json"))
            api(datetime())
        }

        // The CryptoKit-backed ML-DSA provider needs the cinterop above, which only exists on macOS hosts.
        iosMain {
            kotlin.srcDir(if (HostManager.hostIsMac) "src/iosMain/cryptokit" else "src/iosMain/nocryptokit")
        }

        jvmMain.dependencies {
            api(libs.yamltk)
            // ML-DSA on the JVM (verifier, tests): used as a provider instance, never registered globally.
            api(bouncycastle("bcprov", "jdk18on"))
        }

        jvmTest.dependencies {
            implementation(serialization("cbor"))
            implementation(libs.schemakenerator.core)
            implementation(libs.schemakenerator.serialization)
            implementation(libs.schemakenerator.jsonschema)
            implementation(project(":roboto"))
        }
    }
}

setupDokka(
    baseUrl = "https://github.com/a-sit-plus/warden-supreme/tree/main/supreme",
)
val javadocRedirectJar = tasks.named<Jar>("javadocRedirectJar")

dokka.dokkaSourceSets.named("commonMain") {
    // Dokka 2.2.0 crashes while translating context-parameter property getters: Kotlin/dokka#4519.
    sourceRoots.setFrom(fileTree("src/commonMain/kotlin") {
        exclude("AttestedAttributesAccessor.kt")
    })
}

dokka.dokkaSourceSets.named("commonMain") {
    // Dokka 2.2.0 crashes while translating context-parameter property getters: Kotlin/dokka#4519.
    sourceRoots.setFrom(fileTree("src/commonMain/kotlin") {
        exclude("AttestedAttributesAccessor.kt")
    })
}

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocRedirectJar)
            pom {
                name.set("Warden Supreme Commons")
                description.set("Attestation datatypes and utilities; part of the WARDEN Supreme integrated key attestation suite")
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

// Standalone simulator spawns have no usable Keychain (errSecNotAvailable), which the ML-DSA iOS tests need.
// Run on a booted device instead (as Signum does); the device is booted on demand and left running.
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>().configureEach {
    standalone.set(false)
    doFirst {
        providers.exec {
            commandLine("xcrun", "simctl", "boot", device.get())
            isIgnoreExitValue = true
        }.result.get()
        providers.exec {
            commandLine("xcrun", "simctl", "bootstatus", device.get(), "-b")
        }.result.get().assertNormalExitValue()
    }
}
