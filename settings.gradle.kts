rootProject.name = "Warden-Supreme"
pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

include("makoto")
include("makoto-diag")
include("roboto")
include("roboto-diag")
project(":makoto").projectDir = file("serverside/makoto")
project(":roboto").projectDir = file("serverside/roboto")
project(":roboto-diag").projectDir = file("utils/roboto-diag")
project(":makoto-diag").projectDir = file("utils/makoto-diag")

include("supreme-verifier")
include("supreme-common")
include("supreme-client")
project(":supreme-verifier").projectDir = file("supreme/verifier")
project(":supreme-common").projectDir = file("supreme/common")
project(":supreme-client").projectDir = file("supreme/client")

include("config-hoplite")
project(":config-hoplite").projectDir = file("supreme/config-hoplite")
include("config-spring")
project(":config-spring").projectDir = file("supreme/config-spring")
include("config-spring-test")
project(":config-spring-test").projectDir = file("supreme/config-spring-test")

include("collector-shared")
include("collector-app")
include("collector-backend")
include("collector-android")
project(":collector-shared").projectDir = file("collector/shared")
project(":collector-app").projectDir = file("collector/app")
project(":collector-backend").projectDir = file("collector/backend")
project(":collector-android").projectDir = file("collector/androidApp")
