import at.asitplus.gradle.exportXCFramework
import at.asitplus.gradle.ktor


plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("at.asitplus.gradle.conventions")
    id("de.infix.testBalloon")
    id("co.touchlab.skie") version "0.10.14"
}


val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion

kotlin {
    iosArm64()
    iosSimulatorArm64()


    sourceSets {
        all { languageSettings.optIn("kotlin.ExperimentalUnsignedTypes") }

        iosMain.dependencies {
            implementation(project(":supreme-client"))
            implementation(ktor("client-darwin"))
        }
    }
}


skie {
    build {
        produceDistributableFramework()
    }
    analytics {
        disableUpload.set(true)
    }
}

exportXCFramework("WardenSupreme", transitiveExports = false, static = true) {

}
