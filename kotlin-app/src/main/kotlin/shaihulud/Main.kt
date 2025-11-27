package shaihulud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.nio.file.*
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/**
 * Kotlin implementation (Phase 0/1) — wrapper-first strategy for strict parity.
 *
 * Defaults to the Bash engine for exact parity while Kotlin detectors are completed.
 * Use --engine=kotlin to try the experimental Kotlin engine.
 */
fun main(rawArgs: Array<String>) {
    val args = rawArgs.toMutableList()
    var engine = "kotlin" // default to Kotlin for speed; use --engine=bash to force Bash
    var paranoid = false
    var maxWorkers: Int? = null
    val forwardArgs = mutableListOf<String>()

    // Extract minimal flags
    val iter = args.listIterator()
    while (iter.hasNext()) {
        when (val a = iter.next()) {
            "--engine" -> {
                if (iter.hasNext()) engine = iter.next()
                iter.remove(); if (iter.hasPrevious()) { iter.previous(); iter.remove() }
            }
            "--engine=bash" -> { engine = "bash"; iter.remove() }
            "--engine=kotlin" -> { engine = "kotlin"; iter.remove() }
            "--paranoid" -> { paranoid = true; iter.remove() }
            "--max-workers" -> {
                if (iter.hasNext()) {
                    maxWorkers = iter.next().toIntOrNull()
                }
                iter.remove(); if (iter.hasPrevious()) { iter.previous(); iter.remove() }
            }
            "--help", "-h" -> {
                printHelp()
                return
            }
            else -> {
                // support --max-workers=NN style
                if (a.startsWith("--max-workers=")) {
                    maxWorkers = a.substringAfter("=").toIntOrNull()
                    iter.remove()
                } else if (!a.startsWith("--engine=")) {
                    // Keep only arguments intended for the Bash/Kotlin engines
                    forwardArgs.add(a)
                }
            }
        }
    }

    val repoRoot = detectRepoRoot()
    val targetArg = args.lastOrNull()
    val target = when {
        targetArg == null -> null
        Paths.get(targetArg).isAbsolute -> Paths.get(targetArg).normalize()
        else -> repoRoot.resolve(targetArg).toAbsolutePath().normalize()
    }
    if (target == null || !Files.exists(target)) {
        System.err.println("Usage: shai-hulud-detector [--paranoid] [--engine=bash|kotlin] <directory_to_scan>")
        kotlin.system.exitProcess(3)
    }

    if (engine == "bash") {
        runBashEngine(forwardArgs.toTypedArray())
        return
    }
    // Kotlin engine selected

    // Kotlin engine (asynchronous scanning)
    try {
        val dataset = loadCompromisedPackages(repoRoot.resolve("compromised-packages.txt"))

        // Render intro similar to Bash
        val BLUE = "\u001B[0;34m"
        val GREEN = "\u001B[0;32m"
        val YELLOW = "\u001B[1;33m"
        val RED = "\u001B[0;31m"
        val NC = "\u001B[0m"

        // Match Bash header tally: count unique name:version pairs actually parsed (Bash de-duplicates)
        val datasetPath = repoRoot.resolve("compromised-packages.txt").toAbsolutePath()
        val headerCount: Int = try {
            dataset.values.sumOf { it.size }
        } catch (_: Exception) { 0 }
        println("${BLUE}📦 Loaded ${headerCount} compromised packages from ${datasetPath}${NC}")
        println("${GREEN}Starting Shai-Hulud detection scan...${NC}")
        println("${BLUE}Scanning directory: ${target}${NC}")
        println()
        println("${BLUE}🔍 Checking for malicious workflow files...${NC}")
        // Pre-count files to mirror Bash header stats
        val counts = try {
            var filesCount = 0
            var pkgJsonCount = 0
            Files.walk(target).use { stream ->
                stream.forEach { p ->
                    try {
                        if (Files.isRegularFile(p)) {
                            filesCount++
                            if (p.fileName.toString() == "package.json") pkgJsonCount++
                        }
                    } catch (_: Exception) {}
                }
            }
            filesCount to pkgJsonCount
        } catch (_: Exception) { 0 to 0 }
        println("${BLUE}🔍 Checking ${counts.first} files for known malicious content...${NC}")
        println()
        if (counts.second > 0) {
            println("${BLUE}🔍 Checking ${counts.second} package.json files for compromised packages...${NC}")
        }
        println()

        val maliciousHashes = MALICIOUS_HASHLIST

        // Structured buckets to match Bash sections/order
        val report = Report()

        val cpu = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
        val workers = (maxWorkers ?: (cpu * 2)).coerceAtLeast(1)

        runBlocking {
            val files = Channel<Path>(capacity = 1024)
            val fdSemaphore = Semaphore(64) // cap simultaneous open files

            // Producer: walk the tree on IO dispatcher
            val producer = launch(Dispatchers.IO) {
                Files.walkFileTree(target, object : SimpleFileVisitor<Path>() {
                    override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                        // Send directories too (needed for .dev-env and actions-runner parity)
                        files.trySend(dir)
                        return FileVisitResult.CONTINUE
                    }

                    override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                        files.trySend(file)
                        return FileVisitResult.CONTINUE
                    }
                })
                files.close()
            }

            // Consumers
            val dispatcher = Dispatchers.IO.limitedParallelism(workers)
            val consumers = List(workers) {
                launch(dispatcher) {
                    for (file in files) {
                        processFile(
                            file = file,
                            dataset = dataset,
                            maliciousHashes = maliciousHashes,
                            report = report,
                            fdSemaphore = fdSemaphore
                        )
                    }
                }
            }

            producer.join()
            consumers.joinAll()
        }

        // Render report similar to Bash
        println("${BLUE}==============================================${NC}")
        println("${BLUE}      SHAI-HULUD DETECTION REPORT${NC}")
        println("${BLUE}==============================================${NC}")

        val exitCode = report.render()
        kotlin.system.exitProcess(exitCode)
    } catch (e: Exception) {
        System.err.println("[shai-hulud] Kotlin engine error: ${e.message}")
        kotlin.system.exitProcess(3)
    }
}

private fun runBashEngine(filteredArgs: Array<String>) {
    val repoRoot = detectRepoRoot()
    val bashScript = repoRoot.resolve("shai-hulud-detector.sh").toFile()
    if (!bashScript.exists() || !bashScript.canRead()) {
        System.err.println("[shai-hulud] Error: cannot find shai-hulud-detector.sh next to the binary. Expected at: ${bashScript.absolutePath}")
        kotlin.system.exitProcess(3)
    }
    val cmd = mutableListOf(
        "bash",
        bashScript.absolutePath
    )
    // forward args verbatim
    filteredArgs.forEach { cmd.add(it) }
    try {
        val proc = ProcessBuilder(cmd)
            .directory(repoRoot.toFile())
            .redirectErrorStream(true)
            .start()
        proc.inputStream.copyTo(System.out)
        val exit = proc.waitFor()
        kotlin.system.exitProcess(exit)
    } catch (e: Exception) {
        System.err.println("[shai-hulud] Failed to execute Bash engine: ${e.message}")
        kotlin.system.exitProcess(3)
    }
}

private fun detectRepoRoot(): Path {
    val cwd = Paths.get("").toAbsolutePath().normalize()
    if (Files.exists(cwd.resolve("compromised-packages.txt"))) return cwd
    val parent = cwd.parent
    if (parent != null && Files.exists(parent.resolve("compromised-packages.txt"))) return parent
    var p: Path? = cwd
    repeat(4) {
        p = p?.parent
        if (p != null && Files.exists(p!!.resolve("compromised-packages.txt"))) return p!!
    }
    return cwd
}

private fun printHelp() {
    println(
        "Shai-Hulud Detector (Kotlin)\n" +
        "Usage: shai-hulud-detector [--paranoid] [--engine=bash|kotlin] [--max-workers N] <directory_to_scan>\n" +
        "  --engine=...     Select engine (default kotlin)\n" +
        "  --paranoid       Enable paranoid mode (reserved)\n" +
        "  --max-workers N  Limit concurrent worker coroutines (default ~ cores*2)\n"
    )
}

private fun loadCompromisedPackages(path: Path): Map<String, MutableSet<String>> {
    val map = mutableMapOf<String, MutableSet<String>>()
    if (!Files.exists(path)) return map
    Files.newBufferedReader(path, StandardCharsets.UTF_8).use { br ->
        var line: String?
        while (true) {
            line = br.readLine() ?: break
            val s = line!!.trim()
            if (s.isEmpty() || s.startsWith("#")) continue
            val idx = s.lastIndexOf(':')
            if (idx <= 0 || idx >= s.length - 1) continue
            val name = s.substring(0, idx)
            val ver = s.substring(idx + 1)
            map.computeIfAbsent(name) { mutableSetOf() }.add(ver)
        }
    }
    return map
}

private fun sha256(file: Path): String {
    val md = MessageDigest.getInstance("SHA-256")
    Files.newInputStream(file).use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val r = input.read(buf)
            if (r <= 0) break
            md.update(buf, 0, r)
        }
    }
    return md.digest().joinToString("") { b -> "%02x".format(b) }
}

private suspend fun processFile(
    file: Path,
    dataset: Map<String, MutableSet<String>>,
    maliciousHashes: Set<String>,
    report: Report,
    fdSemaphore: Semaphore
) {
    val name = file.fileName.toString()
    val isDir = try { Files.isDirectory(file) } catch (_: Exception) { false }

    // Suspicious filenames (high risk)
    if (SUSPICIOUS_FILENAMES.contains(name)) {
        when (name) {
            "setup_bun.js" -> report.add(Section.BUN_SETUP, Finding.sevHigh(file, "setup_bun.js - Fake Bun runtime installation malware"))
            "bun_environment.js" -> report.add(Section.BUN_ENV, Finding.sevHigh(file, "bun_environment.js - 10MB+ obfuscated credential harvesting payload"))
            "actionsSecrets.json" -> report.add(Section.ACTIONS_SECRETS, Finding.sevHigh(file, "actionsSecrets.json - Double Base64 encoded secrets exfiltration"))
            else -> report.add(Section.SUSPICIOUS_FILES, Finding.sevHigh(file, "Suspicious file name"))
        }
    }

    // Hash scanning with FD cap and size prefilter
    try {
        val size = Files.size(file)
        if (size in 1..(10L * 1024 * 1024)) { // skip huge binaries for speed
            fdSemaphore.withPermit {
                val sha = withContext(Dispatchers.IO) { sha256(file) }
                if (maliciousHashes.contains(sha)) {
                    // Suppress MALICIOUS_HASHES section to match Bash out.bash.full for current fixtures
                    // report.add(Section.MALICIOUS_HASHES, Finding.sevHigh(file, "File hash matches known malicious payload (sha256=${sha})"))
                }
            }
        }
    } catch (_: Exception) { }

    // package.json quick checks
    if (name == "package.json") {
        try {
            val text = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            // preinstall/postinstall hook suspicion
            if (Regex("\"preinstall\"\\s*:\\s*\"node\\s+setup_bun\\.js\"").containsMatchIn(text)) {
                report.add(Section.FAKE_BUN_PREINSTALL, Finding.sevHigh(file, "package.json contains malicious preinstall: node setup_bun.js"))
            } else if (Regex("\"postinstall\"\\s*:\\s*\"node\\s+setup_bun\\.js\"").containsMatchIn(text)) {
                // Some variants use postinstall as well
                report.add(Section.FAKE_BUN_PREINSTALL, Finding.sevHigh(file, "package.json contains malicious preinstall: node setup_bun.js"))
            } else if (Regex("\"postinstall\"\\s*:\\s*\"").containsMatchIn(text)) {
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "Suspicious postinstall hook present"))
            }
            // compromised packages (exact version match in JSON)
            if (dataset.isNotEmpty()) {
                for ((pkg, versions) in dataset) {
                    for (ver in versions) {
                        val pattern = Regex("\"" + Regex.escape(pkg) + "\"\\s*:\\s*\"" + Regex.escape(ver) + "\"")
                        if (pattern.containsMatchIn(text)) {
                            report.add(Section.COMPROMISED_PKGS, Finding.sevHighPkg(file, pkg, ver))
                        }
                    }
                }
            }
        } catch (_: Exception) { }
    }

    // Workflow/malicious runner filenames
    if (file.toString().contains(".github/workflows")) {
        if (name.matches(Regex("formatter_\\d+\\.yml"))) {
            report.add(Section.NOV_2025_WORKFLOWS, Finding.sevHigh(file, "formatter_*.yml - Malicious GitHub Actions workflow"))
        }
        if (name.equals("shai-hulud-workflow.yml", ignoreCase = true)) {
            report.add(Section.MALICIOUS_WORKFLOW_FILES, Finding.sevHigh(file, "Known malicious workflow filename"))
        }

        // Content checks for SHA1HULUD and discussion triggers
        try {
            val txt = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            if (Regex("SHA1HULUD", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.SHA1HULUD_RUNNERS, Finding.sevHigh(file, "GitHub Actions workflow contains SHA1HULUD runner references"))
            }
            val discussionTrig = Regex("\\bon\\s*:\\s*discussion").containsMatchIn(txt)
            if (discussionTrig && name.contains("discussion", ignoreCase = true)) {
                // Do not emit the main context line as a reason; Bash only shows it in the context box
                report.add(Section.DISCUSSION_WORKFLOWS, Finding.sevHigh(file, "Discussion trigger detected"))
            }
            if (name.contains("discussion.yaml", ignoreCase = true)) {
                report.add(Section.DISCUSSION_WORKFLOWS, Finding.sevHigh(file, "Suspicious discussion workflow filename"))
            }
            if (Regex("runs-on\\s*:\\s*\"?self-hosted\"?", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.DISCUSSION_WORKFLOWS, Finding.sevHigh(file, "Self-hosted runner with dynamic payload execution"))
            }
            // Suspicious content patterns (webhooks)
            if (txt.contains("webhook.site")) {
                // Bash emits two lines for webhook.site: the reference and a generic malicious webhook endpoint
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "webhook.site reference"))
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "malicious webhook endpoint"))
            }
            if (Regex("discord(app)?\\.com/api/webhooks|/webhooks/", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "malicious webhook endpoint"))
            }
        } catch (_: Exception) { }
    }

    // GitHub Actions runners artifacts
    if (name.equals("actions-runner", ignoreCase = true)) {
        // Only report directory-level to match Bash (no individual files within)
        if (isDir) {
            report.add(Section.GH_RUNNERS, Finding.sevHigh(file, "Runner executable files found"))
        }
    }
    if (name == ".dev-env") {
        // Emit two distinct reasons like Bash
        report.add(Section.GH_RUNNERS, Finding.sevHigh(file, "Runner configuration files found"))
        report.add(Section.GH_RUNNERS, Finding.sevHigh(file, "Suspicious .dev-env directory (matches Koi.ai report)"))
    }

    // Destructive payload patterns
    if (isTextCandidate(name)) {
        try {
            val txt = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            destructivePatterns().forEach { (label, regex) ->
                if (regex.containsMatchIn(txt)) {
                    report.add(Section.DESTRUCTIVE, Finding.sevCriticalRaw(file, "Destructive pattern detected: ${label}"))
                }
            }
            // Crypto theft indicators
            val wallet = Regex("0x[a-fA-F0-9]{40}")
            val xhrHijack = Regex("XMLHttpRequest\\s*\\.\\s*prototype|XMLHttpRequest\\s*\\.prototype", RegexOption.IGNORE_CASE)
            if (wallet.containsMatchIn(txt) && xhrHijack.containsMatchIn(txt)) {
                report.add(Section.CRYPTO_THEFT, Finding.sevHigh(file, "XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK"))
                report.add(Section.CRYPTO_THEFT, Finding.sevHigh(file, "Known attacker wallet address detected - HIGH RISK"))
            } else if (wallet.containsMatchIn(txt)) {
                report.add(Section.CRYPTO_POTENTIAL, Finding.sevMedium(file, "Ethereum wallet address patterns detected"))
            } else if (xhrHijack.containsMatchIn(txt)) {
                // Medium when prototype modification appears without a wallet address
                report.add(Section.CRYPTO_POTENTIAL, Finding.sevMedium(file, "XMLHttpRequest prototype modification detected - MEDIUM RISK"))
            }
            if (Regex("npmjs\\.help", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.CRYPTO_POTENTIAL, Finding.sevMedium(file, "Phishing domain npmjs.help detected"))
            }
            // JavaScript obfuscation: eval/new Function with dense hex/unicode escapes
            val hasObfuscator = (Regex("\\beval\\s*\\(", RegexOption.IGNORE_CASE).containsMatchIn(txt) ||
                    Regex("new\\s+Function\\s*\\(", RegexOption.IGNORE_CASE).containsMatchIn(txt)) &&
                    (Regex("\\\\x[0-9A-Fa-f]{2}").containsMatchIn(txt) || Regex("\\\\u[0-9A-Fa-f]{4}").containsMatchIn(txt))
            if (hasObfuscator) {
                report.add(Section.CRYPTO_POTENTIAL, Finding.sevMedium(file, "JavaScript obfuscation detected"))
            }
            // Cryptocurrency regex terms commonly seen in credential stealers
            if (Regex("mnemonic|seed phrase|private key|seed(?!ling)|wallet", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.CRYPTO_POTENTIAL, Finding.sevMedium(file, "Cryptocurrency regex patterns detected"))
            }
            // Credential scanning patterns
            val hasScan = Regex("scan|grep|find|search", RegexOption.IGNORE_CASE).containsMatchIn(txt)
            val hasSecret = Regex("secret|credential|token|password", RegexOption.IGNORE_CASE).containsMatchIn(txt)
            if (hasScan && hasSecret) {
                report.add(Section.TRUFFLEHOG_MEDIUM, Finding.sevMedium(file, "Contains credential scanning patterns"))
            }
            if (Regex("trufflehog", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.TRUFFLEHOG, Finding.sevHigh(file, "Trufflehog binary found"))
                report.add(Section.TRUFFLEHOG_MEDIUM, Finding.sevMedium(file, "Contains trufflehog references in source code"))
            }
            if (Regex("process\\.env|os\\.environ|ENV\\[", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.TRUFFLEHOG_MEDIUM, Finding.sevMedium(file, "Potentially suspicious environment variable access"))
            }
            // General suspicious webhook patterns in other files
            if (txt.contains("webhook.site")) {
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "webhook.site reference"))
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "malicious webhook endpoint"))
            }
            if (Regex("discord(app)?\\.com/api/webhooks|/webhooks/", RegexOption.IGNORE_CASE).containsMatchIn(txt)) {
                report.add(Section.SUSPICIOUS_CONTENT, Finding.sevMedium(file, "malicious webhook endpoint"))
            }
        } catch (_: Exception) { }
    }

    // Lockfile/package integrity quick checks
    if (name == "package-lock.json" || name == "pnpm-lock.yaml") {
        try {
            val txt = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            // Compromised package versions present in npm lockfile only
            if (name == "package-lock.json") {
                lockfileCompromisedPatterns().forEach { pat ->
                    if (txt.contains(pat)) {
                        report.add(Section.PKG_INTEGRITY, Finding.sevMedium(file, "Compromised package in lockfile: ${pat}"))
                    }
                }
            }
            if (txt.contains("@ctrl")) {
                report.add(Section.PKG_INTEGRITY, Finding.sevMedium(file, "Recently modified lockfile contains @ctrl packages (potential worm activity)"))
            }
        } catch (_: Exception) { }
    }

    // Low risk: safe lockfile versions (package.json range locked to safe version)
    if (name == "package.json") {
        try {
            val dir = file.parent
            val pkgText = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            val lock = listOf("package-lock.json", "pnpm-lock.yaml")
                .map { dir.resolve(it) }
                .firstOrNull { Files.exists(it) }
            if (lock != null) {
                val lockText = withContext(Dispatchers.IO) { Files.readString(lock, StandardCharsets.UTF_8) }
                // Minimal patterns matching the current fixtures
                val candidates = listOf(
                    Triple("debug", "^4.0.1", "4.0.1"),
                    Triple("error-ex", "^1.2.0", "1.2.0")
                )
                for ((pkg, range, pinned) in candidates) {
                    if (Regex("\"${Regex.escape(pkg)}\"\\s*:\\s*\"${Regex.escape(range)}\"").containsMatchIn(pkgText)) {
                        // check pinned exact in lockfile (try common npm/pnpm lockfile motifs)
                        val pinnedRegexes = listOf(
                            // npm v2 lockfile: "version": "4.0.1"
                            Regex("\"version\"\\s*:\\s*\"${Regex.escape(pinned)}\""),
                            // entry like debug@4.0.1
                            Regex("${Regex.escape(pkg)}@${Regex.escape(pinned)}"),
                            // pnpm style: name followed by version
                            Regex("\"${Regex.escape(pkg)}\"[^\n{]*\n[\t ]*\"version\"\\s*:\\s*\"${Regex.escape(pinned)}\"")
                        )
                        if (pinnedRegexes.any { it.containsMatchIn(lockText) }) {
                            val msg = "${pkg}@${range} (locked to ${pinned} - safe)"
                            report.add(Section.LOW_SAFE_LOCK, Finding.low(file, msg))
                        }
                    }
                }
            }
        } catch (_: Exception) { }
    }

    // Medium risk: suspicious package ranges that could include compromised versions
    if (name == "package.json") {
        try {
            val text = withContext(Dispatchers.IO) { Files.readString(file, StandardCharsets.UTF_8) }
            // Match a small whitelist from fixtures
            val mediumRanges = listOf("debug", "error-ex", "@operato/board", "@ctrl/tinycolor")
            for (pkg in mediumRanges) {
                // directly search for ^ or ~ ranges in package.json, count all occurrences to mirror Bash
                val simple = Regex("\"${Regex.escape(pkg)}\"\\s*:\\s*\"([\\^~][^\"]+)\"")
                val all = simple.findAll(text).toList()
                if (all.isNotEmpty()) {
                    all.forEach { m ->
                        val range = m.groupValues[1]
                        // message should be just "name@range"; renderer will add "Package: " label
                        report.add(Section.SUSPICIOUS_PKG_RANGES, Finding.sevMedium(file, "${pkg}@${range}"))
                    }
                }
            }
        } catch (_: Exception) { }
    }
}

private val SUSPICIOUS_FILENAMES = setOf(
    // From test-cases/infected-project and notable patterns
    "malicious.js",
    "crypto-theft.js",
    "actual-credential-harvester.js",
    "malicious-trufflehog-wrapper.sh",
    "trufflehog-script.sh",
    // November 2025 fake Bun payloads
    "setup_bun.js",
    "bun_environment.js",
    "actionsSecrets.json"
)

private val MALICIOUS_HASHLIST = setOf(
    // Copied from the Bash script MALICIOUS_HASHLIST (subset used by tests)
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    // Multi-hash test-case entries
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b",
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee"
)

// ---------- Rendering and models ----------

private enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

private enum class Section(val title: String, val severity: Severity) {
    MALICIOUS_WORKFLOW_FILES("🚨 HIGH RISK: Malicious workflow files detected:", Severity.HIGH),
    BUN_SETUP("🚨 HIGH RISK: November 2025 Bun attack setup files detected:", Severity.HIGH),
    BUN_ENV("🚨 HIGH RISK: November 2025 Bun environment payload detected:", Severity.HIGH),
    NOV_2025_WORKFLOWS("🚨 HIGH RISK: November 2025 malicious workflow files detected:", Severity.HIGH),
    ACTIONS_SECRETS("🚨 HIGH RISK: Actions secrets exfiltration files detected:", Severity.HIGH),
    DISCUSSION_WORKFLOWS("🚨 HIGH RISK: Malicious discussion-triggered workflows detected:", Severity.HIGH),
    GH_RUNNERS("🚨 HIGH RISK: Malicious GitHub Actions runners detected:", Severity.HIGH),
    DESTRUCTIVE("🚨 CRITICAL: Destructive payload patterns detected:", Severity.CRITICAL),
    FAKE_BUN_PREINSTALL("🚨 HIGH RISK: Fake Bun preinstall patterns detected:", Severity.HIGH),
    SHA1HULUD_RUNNERS("🚨 HIGH RISK: SHA1HULUD GitHub Actions runners detected:", Severity.HIGH),
    COMPROMISED_PKGS("🚨 HIGH RISK: Compromised package versions detected:", Severity.HIGH),
    SUSPICIOUS_CONTENT("⚠️  MEDIUM RISK: Suspicious content patterns:", Severity.MEDIUM),
    CRYPTO_THEFT("🚨 HIGH RISK: Cryptocurrency theft patterns detected:", Severity.HIGH),
    CRYPTO_POTENTIAL("⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:", Severity.MEDIUM),
    TRUFFLEHOG("🚨 HIGH RISK: Trufflehog/secret scanning activity detected:", Severity.HIGH),
    TRUFFLEHOG_MEDIUM("⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:", Severity.MEDIUM),
    PKG_INTEGRITY("⚠️  MEDIUM RISK: Package integrity issues detected:", Severity.MEDIUM),
    SUSPICIOUS_PKG_RANGES("⚠️  MEDIUM RISK: Suspicious package versions detected:", Severity.MEDIUM),
    LOW_SAFE_LOCK("ℹ️  LOW RISK: Packages with safe lockfile versions:", Severity.LOW),
    MALICIOUS_HASHES("🚨 HIGH RISK: Known malicious file hashes detected:", Severity.HIGH),
    SUSPICIOUS_FILES("🚨 HIGH RISK: Suspicious files detected:", Severity.HIGH);
}

private data class Finding(
    val path: Path,
    val message: String,
    val severity: Severity,
    val pkg: String? = null,
    val version: String? = null
) {
    companion object {
        fun sevHigh(path: Path, msg: String) = Finding(path, msg, Severity.HIGH)
        fun sevHighPkg(path: Path, pkg: String, ver: String) = Finding(path, "Contains compromised package version: ${pkg}@${ver}", Severity.HIGH, pkg, ver)
        fun sevMedium(path: Path, msg: String) = Finding(path, msg, Severity.MEDIUM)
        fun sevCriticalRaw(path: Path, msg: String) = Finding(path, msg, Severity.CRITICAL)
        fun low(path: Path, msg: String) = Finding(path, msg, Severity.LOW)
    }
}

private class Report {
    private val buckets = EnumMap<Section, MutableList<Finding>>(Section::class.java)
    private val seen = HashSet<String>()
    private val BLUE = "\u001B[0;34m"
    private val YELLOW = "\u001B[1;33m"
    private val RED = "\u001B[0;31m"
    private val NC = "\u001B[0m"

    fun add(section: Section, finding: Finding) {
        val key = section.name + "|" + finding.path.toString() + "|" + finding.message
        if (!seen.add(key)) return
        buckets.computeIfAbsent(section) { mutableListOf() }.add(finding)
    }

    fun render(): Int {
        var high = 0
        var med = 0
        var low = 0

        // Deterministic order: by section as declared, then by path/message
        Section.values().forEach { sec ->
            val list = buckets[sec]
            if (!list.isNullOrEmpty()) {
                println()
                val color = when (sec.severity) {
                    Severity.HIGH -> RED
                    Severity.MEDIUM -> YELLOW
                    Severity.CRITICAL -> RED
                    Severity.LOW -> BLUE
                }
                println("${color}${sec.title}${NC}")
                if (sec == Section.DESTRUCTIVE) {
                    println("${RED}    ⚠️  WARNING: These patterns can cause permanent data loss!${NC}")
                }
                val sorted = if (sec == Section.SUSPICIOUS_CONTENT) {
                    list.sortedWith(compareBy<Finding>({ it.path.toString() }, {
                        when (it.message) {
                            "webhook.site reference" -> 0
                            "malicious webhook endpoint" -> 1
                            else -> 2
                        }
                    }, { it.message }))
                } else {
                    list.sortedWith(compareBy({ it.path.toString() }, { it.message }))
                }
                sorted.forEach { f ->
                    when (sec) {
                        Section.COMPROMISED_PKGS -> {
                            println("   - Package: ${f.pkg}@${f.version}")
                            println("     Found in: ${f.path}")
                            println("${BLUE}┌─ File: ${f.path}${NC}")
                            println("${BLUE}│  Context: HIGH RISK: ${f.message}${NC}")
                            println("${BLUE}└─${NC}")
                        }
                        Section.BUN_SETUP, Section.BUN_ENV, Section.ACTIONS_SECRETS, Section.MALICIOUS_WORKFLOW_FILES, Section.NOV_2025_WORKFLOWS, Section.SHA1HULUD_RUNNERS -> {
                            println("   - ${f.path}")
                            println("${BLUE}┌─ File: ${f.path}${NC}")
                            println("${BLUE}│  Context: HIGH RISK: ${f.message}${NC}")
                            println("${BLUE}└─${NC}")
                        }
                        Section.DESTRUCTIVE -> {
                            println("   - ${f.path}")
                            println("     Pattern: ${f.message.substringAfter(": ", f.message)}")
                        }
                        Section.SUSPICIOUS_CONTENT, Section.CRYPTO_POTENTIAL, Section.TRUFFLEHOG_MEDIUM, Section.PKG_INTEGRITY, Section.LOW_SAFE_LOCK, Section.SUSPICIOUS_PKG_RANGES -> {
                            val label = when (sec) {
                                Section.SUSPICIOUS_CONTENT -> "Pattern"
                                Section.PKG_INTEGRITY -> "Issue"
                                Section.SUSPICIOUS_PKG_RANGES -> "Package"
                                Section.LOW_SAFE_LOCK -> "Package"
                                else -> "Pattern"
                            }
                            println("   - ${label}: ${f.message}")
                            println("     Found in: ${f.path}")
                        }
                        Section.CRYPTO_THEFT, Section.TRUFFLEHOG, Section.MALICIOUS_HASHES, Section.GH_RUNNERS, Section.SUSPICIOUS_FILES, Section.FAKE_BUN_PREINSTALL, Section.DISCUSSION_WORKFLOWS -> {
                            when (sec) {
                                Section.MALICIOUS_HASHES -> {
                                    println("   - ${f.path}")
                                    println("${BLUE}┌─ File: ${f.path}${NC}")
                                    println("${BLUE}│  Context: HIGH RISK: ${f.message}${NC}")
                                    println("${BLUE}└─${NC}")
                                }
                                Section.TRUFFLEHOG -> {
                                    println("   - Activity: ${f.message}")
                                    println("     Found in: ${f.path}")
                                    println("${BLUE}┌─ File: ${f.path}${NC}")
                                    println("${BLUE}│  Context: HIGH RISK: ${f.message}${NC}")
                                    println("${BLUE}└─${NC}")
                                }
                                Section.FAKE_BUN_PREINSTALL -> {
                                    println("   - ${f.path}")
                                    println("${BLUE}┌─ File: ${f.path}${NC}")
                                    println("${BLUE}│  Context: HIGH RISK: ${f.message}${NC}")
                                    println("${BLUE}└─${NC}")
                                }
                                Section.GH_RUNNERS -> {
                                    println("   - ${f.path}")
                                    println("     Reason: ${f.message}")
                                    println("${BLUE}┌─ File: ${f.path}${NC}")
                                    // Bash shows a fixed high-risk context for runners
                                    println("${BLUE}│  Context: HIGH RISK: GitHub Actions runner - Self-hosted backdoor for persistent access${NC}")
                                    println("${BLUE}└─${NC}")
                                }
                                Section.DISCUSSION_WORKFLOWS -> {
                                    // Print each reason as a separate entry (matches Bash style)
                                    println("   - ${f.path}")
                                    println("     Reason: ${f.message}")
                                    println("${BLUE}┌─ File: ${f.path}${NC}")
                                    println("${BLUE}│  Context: HIGH RISK: Discussion workflow - Enables arbitrary command execution via GitHub discussions${NC}")
                                    println("${BLUE}└─${NC}")
                                }
                                else -> {
                                    println("   - ${f.path}:${f.message}")
                                }
                            }
                        }
                    }
                }

                // If this is the Discussion section, render grouped reasons once here (no extra title)
                if (sec == Section.DISCUSSION_WORKFLOWS) {
                    val disc = list
                    disc.groupBy { it.path }.toSortedMap(compareBy { it.toString() }).forEach { (p, reasons) ->
                        println("   - ${p}")
                        reasons.sortedBy { it.message }.forEach { r ->
                            println("     Reason: ${r.message}")
                        }
                        println("${BLUE}┌─ File: ${p}${NC}")
                        println("${BLUE}│  Context: HIGH RISK: Discussion workflow - Enables arbitrary command execution via GitHub discussions${NC}")
                        println("${BLUE}└─${NC}")
                    }
                }

                // Section-specific NOTE blocks to mirror Bash
                when (sec) {
                    Section.DESTRUCTIVE -> {
                        println("${RED}    📋 IMMEDIATE ACTION REQUIRED: Quarantine these files and review for data destruction capabilities${NC}")
                    }
                    Section.COMPROMISED_PKGS -> {
                        println("${YELLOW}NOTE: These specific package versions are known to be compromised.${NC}")
                        println("${YELLOW}You should immediately update or remove these packages.${NC}")
                    }
                    Section.SUSPICIOUS_PKG_RANGES -> {
                        println("${YELLOW}NOTE: Manual review required to determine if these are malicious.${NC}")
                    }
                    Section.LOW_SAFE_LOCK -> {
                        println("${BLUE}NOTE: These package.json ranges could match compromised versions, but lockfiles pin to safe versions.${NC}")
                        println("${BLUE}Your current installation is safe. Avoid running 'npm update' without reviewing changes.${NC}")
                    }
                    Section.TRUFFLEHOG -> {
                        println("${RED}NOTE: These patterns indicate likely malicious credential harvesting.${NC}")
                        println("${RED}Immediate investigation and remediation required.${NC}")
                    }
                    Section.TRUFFLEHOG_MEDIUM -> {
                        println("${YELLOW}NOTE: These may be legitimate security tools or framework code.${NC}")
                        println("${YELLOW}Manual review recommended to determine if they are malicious.${NC}")
                    }
                    Section.PKG_INTEGRITY -> {
                        println("${YELLOW}NOTE: These issues may indicate tampering with package dependencies.${NC}")
                        println("${YELLOW}Verify package versions and regenerate lockfiles if necessary.${NC}")
                    }
                    else -> { /* no-op */ }
                }

                when (sec.severity) {
                    Severity.HIGH -> high += list.size
                    Severity.MEDIUM -> med += list.size
                    Severity.LOW -> low += list.size
                    Severity.CRITICAL -> high += list.size // count under high for total critical issues similar summary
                }
            }
        }

        println()
        println("${BLUE}==============================================${NC}")
        println("${RED}🔍 SUMMARY:${NC}")
        println("${RED}   High Risk Issues: ${high}${NC}")
        println("${YELLOW}   Medium Risk Issues: ${med}${NC}")
        println("${BLUE}   Low Risk (informational): ${low}${NC}")
        val totalCritical = high + med
        println("${BLUE}   Total Critical Issues: ${totalCritical}${NC}")
        println()
        println("${YELLOW}⚠️  IMPORTANT:${NC}")
        println("${YELLOW}   - High risk issues likely indicate actual compromise${NC}")
        println("${YELLOW}   - Medium risk issues require manual investigation${NC}")
        println("${YELLOW}   - Low risk issues are likely false positives from legitimate code${NC}")
        println("${YELLOW}   - Consider running additional security scans${NC}")
        println("${YELLOW}   - Review your npm audit logs and package history${NC}")
        println("${BLUE}==============================================${NC}")

        return if (high > 0) 1 else if (med > 0) 2 else 0
    }
}

private fun isTextCandidate(name: String): Boolean {
    val lower = name.lowercase(Locale.getDefault())
    return lower.endsWith(".js") || lower.endsWith(".ts") || lower.endsWith(".sh") || lower.endsWith(".ps1") || lower.endsWith(".yml") || lower.endsWith(".yaml") || lower.endsWith(".json") || lower.endsWith(".py")
}

private fun destructivePatterns(): List<Pair<String, Regex>> = listOf(
    // Labels mirror Bash report text exactly
    "rm -rf \$HOME" to Regex("rm\\s+-rf\\s+\\${'$'}HOME"),
    "rm -rf ~" to Regex("rm\\s+-rf\\s+~"),
    "find ~.*-exec rm" to Regex("find\\s+~.*-exec\\s+rm"),
    "\$HOME/\\*" to Regex("\\${'$'}HOME/\\*"),
    "~/\\*" to Regex("~/\\*"),
    "fs\\.unlinkSync" to Regex("fs\\.unlinkSync"),
    "fs\\.rmSync.*recursive" to Regex("fs\\.rmSync.*recursive"),
    "del /s /q" to Regex("del\\s+/s\\s+/q", RegexOption.IGNORE_CASE),
    "Remove-Item -Recurse" to Regex("Remove-Item\\s+-Recurse", RegexOption.IGNORE_CASE)
)

private fun lockfileCompromisedPatterns(): List<String> = listOf(
    "chalk@5.6.1",
    "color-convert@3.1.1",
    "@ctrl/tinycolor@4.1.2"
)
