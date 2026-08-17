import at.asitplus.gradle.serialization

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.kotlin.multiplatform.library")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()
    android {
        namespace = "at.asitplus.warden.collector.shared"
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":supreme-common"))
            implementation(serialization("json"))
        }
        jvmTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
