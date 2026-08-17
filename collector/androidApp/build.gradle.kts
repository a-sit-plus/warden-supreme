import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // AGP 9 provides built-in Kotlin support, so no org.jetbrains.kotlin.android plugin is applied here.
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.composeCompiler)
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_11
    }
}

dependencies {
    implementation(project(":collector-app"))

    implementation(libs.androidx.activity.compose)

    implementation(libs.compose.uiToolingPreview)
    debugImplementation(libs.compose.uiTooling)
}

android {
    namespace = "at.asitplus.warden.collector"
    // Compose requires compileSdk >= 35; align with :collector-app (36).
    compileSdk = 36

    defaultConfig {
        applicationId = "at.asitplus.warden.collector"
        // minSdk matches the repo-wide android.minSdk (30) so it satisfies :collector-app.
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }
    signingConfigs {
        // Sign with the SAME keystore as the supreme-client android test APK so the installed app's
        // signing-cert digest matches `signerFingerprints` in the backend's supreme.yaml.
        create("attest") {
            storeFile = rootProject.file("supreme/client/keystore.p12")
            storePassword = "123456"
            keyAlias = "key0"
            keyPassword = "123456"
            storeType = "PKCS12"
        }
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/LICENSE.md"
        }
    }
    buildTypes {
        debug {
            // Install/run builds must carry the key0 cert to be attestable.
            signingConfig = signingConfigs.getByName("attest")
        }
        release {
            signingConfig = signingConfigs.getByName("attest")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}
