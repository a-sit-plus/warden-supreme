import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "2.0.20+20240920"
    id("com.android.library") version "8.2.2" apply (false)
}

group = "at.asitplus"


//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("$buildDir/dokka"))
    includes.from("README.md")
    moduleName.set("VERITAS")
}


allprojects {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //Signum snapshot
    }
}