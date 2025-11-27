plugins {
  kotlin("jvm") version "2.0.20"
  id("org.graalvm.buildtools.native") version "0.10.3"
  application
}

repositories { mavenCentral() }

dependencies {
  implementation(kotlin("stdlib"))
  // Minimal concurrency support for async scanning
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
  // Keep test deps light
  testImplementation(kotlin("test"))
}

java {
  // Target 21 to align with GraalVM 21
  toolchain {
    languageVersion.set(JavaLanguageVersion.of(21))
  }
}

application {
  mainClass = "shaihulud.MainKt"
}

tasks.test {
  useJUnitPlatform()
}

graalvmNative {
  binaries {
    named("main") {
      imageName.set("shai-hulud-detector")
      buildArgs.addAll(listOf(
        "--no-fallback",
        "--initialize-at-build-time",
        "-H:+ReportExceptionStackTraces"
      ))
    }
  }
}

// Bundle the Bash script and dataset into the JVM application distribution so
// that "installDist" produces a self-contained folder the same way CI artifacts do.
distributions {
  main {
    contents {
      from(rootProject.file("shai-hulud-detector.sh")) { into(".") }
      from(rootProject.file("compromised-packages.txt")) { into(".") }
      from(rootProject.file("README.md")) { into(".") }
      from(rootProject.file("LICENSE")) { into(".") }
    }
  }
}

// Create a zip that contains the native binary alongside the same data files.
// Result: build/distributions/shai-hulud-detector-native-<os>.zip
val packageNative by tasks.registering(Zip::class) {
  dependsOn(tasks.named("nativeCompile"))
  val nativeDir = layout.buildDirectory.dir("native/nativeCompile")
  from(nativeDir) { include("shai-hulud-detector*") ; into(".") }
  from(rootProject.file("shai-hulud-detector.sh")) { into(".") }
  from(rootProject.file("compromised-packages.txt")) { into(".") }
  from(rootProject.file("README.md")) { into(".") }
  from(rootProject.file("LICENSE")) { into(".") }
  archiveBaseName.set("shai-hulud-detector-native")
  // Add a small OS hint to the artifact name to help identify downloads
  val os = org.gradle.internal.os.OperatingSystem.current()
  val osName = when {
    os.isWindows -> "windows"
    os.isMacOsX -> "macos"
    else -> "linux"
  }
  archiveClassifier.set(osName)
}

// Convenience task to clean locally generated diff/exit artifacts in the repo root.
// It does NOT remove anything under version control other than these transient files.
tasks.register<Delete>("cleanRepoOutputs") {
  // Historic files created by parity harness runs
  val root = rootProject.layout.projectDirectory.asFile
  delete(
    File(root, "out.bash.clean.txt"),
    File(root, "out.bash.full"),
    File(root, "out.bash.full.new"),
    File(root, "out.bash.infected.txt"),
    File(root, "out.kotlin.full"),
    File(root, "out.kotlin.full.new"),
    File(root, "out.kt.clean.txt"),
    File(root, "out.kt.full"),
    File(root, "out.kt.full.new"),
    File(root, "out.kt.wrap.clean.txt"),
    File(root, "out.native.kt.full"),
    File(root, "out.wrap.clean.txt"),
    File(root, "exit.bash"),
    File(root, "exit.bash.clean"),
    File(root, "exit.kt"),
    File(root, "exit.kt.clean"),
    File(root, "exit.kt.wrap.clean"),
    File(root, "exit.native.kt"),
    File(root, "exit.wrap.clean")
  )
}
