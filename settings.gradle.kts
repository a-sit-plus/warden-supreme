rootProject.name = "VERITAS"
pluginManagement {
    repositories {
        google()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //KOTEST snapshot
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("radix")
include("servus")
include("sanctor")
