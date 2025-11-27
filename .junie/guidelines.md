Shai‑Hulud Detector — Project Guidelines (Kotlin/GraalVM rewrite)

This document distills project‑specific guidance for building, testing, and evolving the Kotlin/GraalVM rewrite of the existing Bash‑based `shai-hulud-detector.sh`. It assumes an advanced developer audience and focuses on exact compatibility, performance, and a safe forward‑upgrade path where the Bash version remains the source of truth for behavior.


1. Goals and non‑goals

- Primary goals
  - Output compatibility: CLI UX, flags, exit codes, diagnostics, and line ordering should match the Bash detector closely enough for CI drop‑in replacement. Minor whitespace differences are acceptable, but avoid reflowing text or reordering sections unless explicitly stabilized.
  - Faster execution at scale: Kotlin with coroutines and structured concurrency must outperform the Bash implementation on large repositories (node_modules, monorepos, giant lockfiles). Aim for multi‑minute → sub‑minute improvements where IO and parsing dominate.
  - Forward‑upgrade: Keep the Bash script and test‑cases authoritative. The Kotlin port should implement a “parity bench” that continuously diff‑checks its output against the Bash version for every committed change and any future upstream updates of the Bash logic or indicators.

- Non‑goals
  - We do not change the semantics of the detector without first changing the Bash baseline and re‑syncing tests.
  - We avoid adding heavyweight external services or databases; everything remains repo‑local and file‑system driven.


2. Repository layout (current)

- Root contains:
  - `shai-hulud-detector.sh` — canonical behavior reference
  - `compromised-packages.txt` — canonical indicator dataset consumed by Bash
  - `test-cases/` — scenario suites used for I/O parity testing
  - Various README/CHANGELOG/license

- Kotlin rewrite will live in this same worktree (module name suggestions below) while keeping the Bash script and test-cases untouched.


3. Build and configuration — Kotlin + GraalVM native image

3.1 Toolchains

- JDK: Use GraalVM for JDK 21 (CE or EE). Ensure `native-image` is installed:
  - `gu install native-image`
- Build system: Gradle (Kotlin DSL)
- Kotlin: 2.0+ (consistent with Gradle version; 2.0.20+ recommended)
- Native image plugin: `org.graalvm.buildtools.native` Gradle plugin
- Dependencies:
  - `org.jetbrains.kotlinx:kotlinx-coroutines-core`
  - `org.jetbrains.kotlinx:kotlinx-serialization-json`
  - SemVer parsing: prefer `com.vdurmont:semver4j` or `com.github.zafarkhaja:java-semver` (pick one and wrap via an adapter to ease swap)
  - YAML (for reading minimal bits of GitHub workflows if needed): `org.snakeyaml:snakeyaml-engine` (engine v2)
  - CLI parser: keep minimal; either no parser (manual) to preserve Bash parity, or `kotlinx-cli` with strict option mapping

3.2 Gradle bootstrap (no files added here; commands for local setup)

Run locally in the repository root:

```bash
gradle --version  # ensure Gradle 8.7+

# Initialize module
mkdir -p kotlin-app/src/{main,test}/kotlin
cat > settings.gradle.kts <<'SET'
rootProject.name = "shai-hulud-detect"
include("kotlin-app")
SET

cat > kotlin-app/build.gradle.kts <<'SET'
plugins {
  kotlin("jvm") version "2.0.20"
  id("org.graalvm.buildtools.native") version "0.10.3"
  kotlin("plugin.serialization") version "2.0.20"
  application
}

repositories { mavenCentral() }

dependencies {
  implementation(kotlin("stdlib"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
  implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
  implementation("com.vdurmont:semver4j:3.1.0")
  testImplementation(kotlin("test"))
}

application { mainClass = "shaihulud.MainKt" }

tasks.test { useJUnitPlatform() }

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
SET

cat > kotlin-app/src/main/kotlin/shaihulud/Main.kt <<'SET'
package shaihulud

fun main(args: Array<String>) {
    // Stub to be replaced with full parity implementation.
    // For now, forward to Bash to guarantee identical behavior until feature parity is reached.
    // The Kotlin port should replace this with native logic once the test parity harness passes.
    val proc = ProcessBuilder(listOf("bash", "./shai-hulud-detector.sh") + args)
        .redirectErrorStream(true)
        .start()
    proc.inputStream.copyTo(System.out)
    val exit = proc.waitFor()
    kotlin.system.exitProcess(exit)
}
SET
```

3.3 Build commands

- JVM run (delegates to Bash until parity):
  - `./gradlew :kotlin-app:run --args="<args>"`
- Native image:
  - `./gradlew :kotlin-app:nativeCompile`
  - Native binary at `kotlin-app/build/native/nativeCompile/shai-hulud-detector`

Notes
- Prefer GraalVM 21+ for better startup/perf and reduced reflection needs.
- Keep reflection minimal. If using YAML/JSON parsing or ServiceLoader, configure `reflect-config.json` automatically through the Gradle plugin where possible.


4. Behavior compatibility strategy

- CLI parity contract
  - Options: mirror `--paranoid`, `--help`, `--version`, positional target path, and any quiet/verbose flags present in Bash.
  - Exit codes: 0 clean, 1 high‑risk, 2 medium‑risk (same as README). Treat unknown errors as exit 3 with a clear error header (but do NOT change Bash semantics unless upstream does).
  - Output structure: retain section headers and item ordering where practical; if concurrency could reorder lines, buffer and sort within each section according to Bash order rules before printing.

- Dataset parity
  - Treat `compromised-packages.txt` as a data file. Load it directly instead of embedding constants. That ensures updates are picked up without rebuilding.
  - Consider a light DSL/format adapter so that Bash and Kotlin read from the same file.

- Feature toggles for migration
  - Start with a “Bash pass‑through” mode (see stub main above) to ship a native wrapper quickly.
  - Implement Kotlin detectors incrementally behind flags: `--engine=bash|kotlin|auto`. In `auto`, prefer Kotlin engine when parity tests pass for the target tree size; otherwise fall back to Bash.
  - Keep hard kills for risky discrepancies (e.g., if Kotlin finds fewer critical items than Bash, optionally fail closed when `--strict-parity` is set in CI).


5. Performance design (Kotlin)

- IO strategy
  - Use `java.nio.file` (walkFileTree) with bounded concurrency for directory scans. Use a dispatcher tuned to CPU+IO: `Dispatchers.IO.limitedParallelism(k)` where `k ~= (cores * 2 .. cores * 4)`.
  - Apply fast prefilters: filename suffixes, size thresholds (skip 10MB+ binaries unless specific signatures require scanning), and early content checks before expensive regex.

- Regex/signature scanning
  - Precompile regex patterns and share across coroutines. Avoid excessive backtracking; prefer simple contains checks for common indicators before regex.
  - For multi‑hash payloads (e.g., `bun_environment.js`), compute fast hashes (xxhash64) in addition to SHA-256 when comparing known blobs.

- Lockfile and `package.json` handling
  - For `package-lock.json`/`pnpm-lock.yaml`, stream parse if possible; otherwise, read once and parse to a minimal DOM.
  - Implement semver range resolution using `semver4j` and stabilize to Bash’s inclusive/exclusive logic.

- Batching and de‑duplication
  - Coalesce findings per file and per package to match Bash’s reporting granularity. Emit in deterministic order.


6. Testing — Parity and performance

6.1 Local requirements

- Shell: Bash 4+ (WSL/Linux/macOS). On Windows CI, use WSL or Git‑Bash.
- Node is NOT required to run tests; we only read files.

6.2 Parity harness (manual, no repo changes)

Run from repo root. Examples below assume Linux/macOS shell:

```bash
# 0) Ensure Bash baseline runs
chmod +x ./shai-hulud-detector.sh
./shai-hulud-detector.sh test-cases/clean-project > out.bash.clean.txt;  echo $? > exit.bash.clean
./shai-hulud-detector.sh test-cases/infected-project > out.bash.infected.txt; echo $? > exit.bash.infected

# 1) Build Kotlin wrapper/native image
./gradlew :kotlin-app:run --args="test-cases/clean-project" > out.kt.clean.txt;      echo $? > exit.kt.clean
./gradlew :kotlin-app:run --args="test-cases/infected-project" > out.kt.infected.txt; echo $? > exit.kt.infected

# 2) Compare exit codes and key lines
diff -u exit.bash.clean exit.kt.clean
diff -u exit.bash.infected exit.kt.infected

# 3) Compare normalized outputs (trim timestamps/paths if any; Bash currently prints deterministic text)
diff -u <(sed 's|\\|/|g' out.bash.clean.txt) <(sed 's|\\|/|g' out.kt.clean.txt)
diff -u <(sed 's|\\|/|g' out.bash.infected.txt) <(sed 's|\\|/|g' out.kt.infected.txt)

# 4) Paranoid mode sample
./shai-hulud-detector.sh --paranoid test-cases/comprehensive-test > out.bash.paranoid.txt; echo $? > exit.bash.paranoid
./gradlew :kotlin-app:run --args="--paranoid test-cases/comprehensive-test" > out.kt.paranoid.txt; echo $? > exit.kt.paranoid
diff -u exit.bash.paranoid exit.kt.paranoid
diff -u out.bash.paranoid.txt out.kt.paranoid.txt || true
```

Notes
- During early stages (wrapper mode), outputs will be identical by definition since Kotlin delegates to Bash. As native Kotlin logic is implemented feature by feature, use the same harness. Gate merges on green diffs.
- Avoid committing `out.*` artifacts; they are local.

6.3 Adding a new test (guidelines)

- Place a minimal fixture under `test-cases/<name>/...` mirroring real‑world files that triggered detections.
- Keep files as small as possible while preserving the detection signal.
- Do not add executable scripts that alter the repo state (except the existing ones already present for reference); test files must be read‑only artifacts.
- Validate by running both engines and diffing the outputs as shown above. Do not change existing tests; add only.

6.4 Simple demonstration test to run locally

```bash
# Clean project should yield exit 0 and no high/medium risk findings
./shai-hulud-detector.sh test-cases/clean-project; echo $?  # expect 0

# Known infected project should yield high‑risk (exit 1)
./shai-hulud-detector.sh test-cases/infected-project; echo $?  # expect 1
```

Important
- In this environment, we cannot run Bash directly from Windows PowerShell without WSL/Git‑Bash. Run the above in WSL or a POSIX shell. Keep Kotlin CI jobs running on Linux runners to execute both engines.


7. Kotlin implementation plan (incremental)

Phase 0 — Wrapper and scaffolding
- Create Gradle module and native image build. CLI args are forwarded to Bash for immediate usability. Add `--engine` flag but keep default `bash` while implementing features.

Phase 1 — Data and parsers
- Implement readers for:
  - `package.json`, `package-lock.json`, `pnpm-lock.yaml`
  - `compromised-packages.txt` (keep format identical)
  - GitHub workflow YAML (only patterns relevant to SHA1HULUD runners)
- Implement semver range checks to mirror Bash logic.

Phase 2 — File scanning + heuristics
- Implement async file walker with bounded parallelism and back‑pressure.
- Port detectors in small slices with unit tests focused per detector:
  - XMLHttpRequest hijack indicators
  - TruffleHog invocation / wrapper patterns
  - November 2025 fake Bun payload signatures (`setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`)
  - Suspicious GitHub Actions runners and workflow files
  - Namespace/package family warnings and typosquatting heuristics

Phase 3 — Output compatibility and stability
- Replicate Bash headers and ordering. Add golden files derived from Bash outputs for core fixtures; compare byte‑for‑byte.

Phase 4 — Performance hardening
- Tune dispatcher parallelism, memory usage, and I/O chunking. Add a micro‑benchmark that walks `test-cases/` and a large synthetic directory to validate speedups. Maintain a `--max-workers` flag for manual tuning.

Phase 5 — Default to Kotlin engine
- When parity harness is green and performance targets are met, flip default `--engine=auto` to prefer Kotlin and keep `--engine=bash` escape hatch.


8. Code style and conventions (Kotlin)

- Keep modules small and functions pure where possible; make detectors stateless `suspend` functions that return findings.
- Centralize patterns and constants. No magic strings/regex in call‑sites.
- Provide a stable `Finding` model with fields: id, severity, location, message, context. Implement deterministic `toString()` that renders exactly like Bash sections.
- Avoid global mutable state; pass coroutine scope/context explicitly. Use `SupervisorJob` with structured concurrency and cancellation on SIGINT.


9. CI recommendations

- Linux runner with GraalVM 21+. Jobs:
  1) Bash parity job: run Bash over all `test-cases/` and save artifacts.
  2) Kotlin JVM run over same cases; diff outputs and exit codes.
  3) Native image build; run native over same cases; diff again.
  4) Optional: performance smoke test on a large mock tree; fail if regression > X%.

- Do not push artifacts or additional files to the repository except source changes. Keep parity artifacts as CI artifacts only.


10. Upgrade path when Bash upstream changes

- Treat `shai-hulud-detector.sh` as the spec. On update:
  - Re-run parity harness; collect diffs.
  - If only dataset changed, no code changes needed; commit the dataset and ensure Kotlin reads it at runtime.
  - If logic changed, implement the corresponding Kotlin detector deltas and update golden outputs.
  - Keep a changelog entry referencing the upstream commit/date.


11. Known pitfalls and edge cases

- Concurrency can reorder findings; buffer and sort to match Bash expectations.
- Large `node_modules/` can exhaust file descriptors; implement a semaphore for open file count.
- Binary or giant files: short‑circuit by size and magic bytes; don’t run pathological regex across multi‑MB blobs unless the specific signature requires it (e.g., `bun_environment.js`).
- Windows paths: normalize to POSIX‑like slashes in output if the Bash baseline assumes that; or conditionally map during diff for parity tests.


12. Current session note

- Due to the execution constraints of this environment, we did not run the Bash script here. The instructions above detail how to run and validate locally (WSL/Linux/macOS). Before committing Kotlin logic that diverges from the wrapper, please run the parity checks locally or in CI as described.


Appendix A — Minimal engine interface (suggested)

```kotlin
interface DetectorEngine {
  suspend fun scan(target: Path, options: Options): Result
}

data class Options(
  val paranoid: Boolean = false,
  val maxWorkers: Int = Runtime.getRuntime().availableProcessors() * 2,
  val strictParity: Boolean = false
)

data class Result(
  val exitCode: Int,
  val lines: List<String> // already rendered lines to match Bash
)
```

Implement `BashEngine` (delegates to the script) and `KotlinEngine` (native logic). The CLI selects one and prints `lines` verbatim, returning `exitCode` as process status.
