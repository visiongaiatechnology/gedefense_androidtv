plugins {
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Vendored, dependency-free GeDefense core (ThreatIndex, PrivacyIntelligenceRegistry, IpPrefix).
    implementation(project(":core"))
}

tasks.register<JavaExec>("tvCoreCheck") {
    group = "verification"
    description = "Runs the dependency-free GeDefense TV domain verification harness."
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("de.visiongaia.gedefense.tv.core.TvCoreTestMainKt")
}

tasks.register<JavaExec>("tvV2Check") {
    group = "verification"
    description = "Runs the GeDefense TV V2 traffic/privacy/XDR domain verification harness."
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("de.visiongaia.gedefense.tv.core.V2CoreTestMainKt")
}

tasks.register<JavaExec>("tvKineticCheck") {
    group = "verification"
    description = "Runs the GeDefense TV V2.1 anomaly/containment (Kinetic-Lite) verification harness."
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("de.visiongaia.gedefense.tv.core.KineticTestMainKt")
}
