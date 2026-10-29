plugins {
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

tasks.register<JavaExec>("coreCheck") {
    group = "verification"
    description = "Runs GeDefense Mobile dependency-free core verification harness."
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("de.visiongaia.gedefense.mobile.core.CoreTestMainKt")
}
