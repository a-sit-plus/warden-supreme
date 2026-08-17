import at.asitplus.gradle.ktor
import at.asitplus.gradle.serialization

plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("org.jetbrains.compose")
    id("org.jetbrains.kotlin.plugin.compose")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

kotlin {
    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "Shared"
            isStatic = true
        }
    }

    android {
        // Distinct from the launcher's applicationId/namespace (at.asitplus.warden.collector);
        // the android namespace only names the R/BuildConfig classes and is independent of the Kotlin package.
        namespace = "at.asitplus.warden.collector.app"
        // Compose Multiplatform 1.11 pulls in androidx.compose.* that require compileSdk >= 35.
        // Override the repo-wide android.compileSdk (34) for this module only.
        compileSdk = 36
        androidResources {
            enable = true
        }
        withHostTest {
            isIncludeAndroidResources = true
        }
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    sourceSets {
        androidMain.dependencies {
            implementation(libs.compose.uiToolingPreview)
            implementation(libs.compose.uiTooling)
            // Ktor client engine so HttpClient() resolves an engine on Android.
            implementation(ktor("client-cio"))
        }
        iosMain.dependencies {
            // Ktor client engine for iOS.
            implementation(ktor("client-darwin"))
        }
        commonMain.dependencies {
            implementation(project(":collector-shared"))
            api(project(":supreme-client"))
            implementation(serialization("json"))

            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.material3)
            implementation(libs.compose.ui)
            implementation(libs.compose.components.resources)
            implementation(libs.compose.uiToolingPreview)
            implementation(libs.androidx.lifecycle.viewmodelCompose)
            implementation(libs.androidx.lifecycle.runtimeCompose)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

// Pin the generated Compose-resources package so it no longer depends on the (now changed)
// root project / module name. Keep it aligned with the imports in commonMain.
compose.resources {
    packageOfResClass = "at.asitplus.warden.collector.generated.resources"
}

dependencies {
    androidRuntimeClasspath(libs.compose.uiTooling)
}
