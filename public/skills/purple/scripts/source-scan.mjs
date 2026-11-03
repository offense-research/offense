// scripts/source-scan-client.mjs
import { execFileSync, spawnSync as spawnSync2 } from "node:child_process";
import { lstat as lstat3, readFile as readFile2, mkdtemp as mkdtemp2, mkdir as mkdir2, writeFile as writeFile2, rename as rename2, rm as rm2 } from "node:fs/promises";
import path3 from "node:path";
import os2 from "node:os";
import { fileURLToPath as fileURLToPath2 } from "node:url";

// agent/zizmor.mjs
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
var ZIZMOR_VERSION = "1.31.1";
var MAX_OUTPUT = 8 * 1024 * 1024;
var MAX_FINDINGS = 500;
var RULES = /* @__PURE__ */ new Set([
  "adhoc-packages",
  "anonymous-definition",
  "archived-uses",
  "artipacked",
  "bot-conditions",
  "cache-poisoning",
  "concurrency-limits",
  "dangerous-triggers",
  "dependabot-cooldown",
  "dependabot-execution",
  "excessive-permissions",
  "forbidden-uses",
  "github-app",
  "github-env",
  "hardcoded-container-credentials",
  "impostor-commit",
  "insecure-commands",
  "insecure-url-scheme",
  "known-vulnerable-actions",
  "misfeature",
  "obfuscation",
  "overprovisioned-secrets",
  "ref-confusion",
  "ref-version-mismatch",
  "secrets-inherit",
  "secrets-outside-env",
  "self-hosted-runner",
  "self-repository",
  "stale-action-refs",
  "superfluous-actions",
  "template-injection",
  "typosquat-uses",
  "undocumented-permissions",
  "unpinned-images",
  "unpinned-tools",
  "unpinned-uses",
  "unredacted-secrets",
  "unsound-condition",
  "unsound-contains",
  "unsound-ternary",
  "use-trusted-publishing"
]);
var REMEDIATION = Object.freeze({
  "template-injection": "Pass untrusted GitHub expressions through step environment variables and quote shell variables. Avoid interpolating expressions directly into executable scripts; verify the workflow still behaves correctly.",
  "dangerous-triggers": "Separate untrusted pull-request code from privileged workflows. Do not check out or execute attacker-controlled code while secrets or write permissions are available.",
  "excessive-permissions": "Declare the minimum GitHub token permissions required for each job. Verify legitimate checkout, reporting and release operations after reducing permissions.",
  "unpinned-uses": "Pin this action to a reviewed full commit SHA and retain its release version in a comment. Verify the selected action revision and configure reviewed updates.",
  "unpinned-images": "Pin the container image to a reviewed immutable digest and verify its intended publisher and upgrade process.",
  artipacked: "Disable persisted checkout credentials when they are not needed and exclude credentials from artifacts. Review whether untrusted code or uploaded artifacts can expose the token.",
  "cache-poisoning": "Separate cache writes across trust boundaries. Ensure untrusted workflows cannot populate a cache later consumed by privileged builds or releases.",
  "github-env": "Do not write untrusted multiline data directly to GitHub environment or path command files. Use a safe delimiter or an alternative data channel and verify downstream behavior.",
  "hardcoded-container-credentials": "Remove the embedded registry credential, revoke and rotate it, and use a scoped secret reference. Inspect previous workflow runs for exposure.",
  "unredacted-secrets": "Prevent secret-derived values from reaching workflow logs or outputs. Revoke and rotate any credential that was already exposed.",
  "secrets-inherit": "Pass only the explicitly required secrets to the reusable workflow and verify its callers and trust boundary.",
  "self-hosted-runner": "Restrict untrusted code from persistent self-hosted runners. Review runner isolation, job permissions and credential lifetime.",
  "use-trusted-publishing": "Use the package registry trusted-publishing flow where supported and grant identity-token permission only to the required release job."
});
var TITLE = Object.freeze({
  "template-injection": "Potential script injection in GitHub Actions",
  "dangerous-triggers": "Untrusted code can cross a privileged workflow boundary",
  "excessive-permissions": "GitHub Actions token permissions exceed the declared need",
  "unpinned-uses": "GitHub Action is referenced by a mutable version",
  "cache-poisoning": "Workflow cache may cross a trust boundary",
  artipacked: "Checkout credentials may be exposed by workflow artifacts"
});
var SEVERITY = Object.freeze({ High: "HIGH", Medium: "MEDIUM", Low: "LOW", Informational: "LOW" });
var CONFIDENCE = /* @__PURE__ */ new Set(["High", "Medium", "Low"]);
function validRelative(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 500 && !value.includes("\\") && !/[\u0000-\u001f\u007f]/u.test(value) && !path.posix.isAbsolute(value) && !value.split("/").some((part) => !part || part === "." || part === "..");
}
function isZizmorInput(value) {
  return validRelative(value) && (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(value) || /(?:^|\/)action\.ya?ml$/.test(value));
}
function localLocation(location2, root, allowed) {
  const value = location2?.symbolic?.key?.Local?.verbatim_path;
  if (typeof value !== "string" || value.length > root.length + 501) return null;
  const relative = path.isAbsolute(value) ? path.relative(root, value) : value.replace(/^\.\//, "");
  if (!validRelative(relative) || !allowed.has(relative)) return null;
  const row = location2?.concrete?.location?.start_point?.row;
  return { file: relative, line: Number.isInteger(row) && row >= 0 && row < 1e6 ? row + 1 : null };
}
function normalized(raw, root, allowed) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || !RULES.has(raw.ident) || !Array.isArray(raw.locations)) return null;
  const locations = [...raw.locations].sort((a, b) => Number(b?.symbolic?.kind === "Primary") - Number(a?.symbolic?.kind === "Primary"));
  const position = locations.map((location2) => localLocation(location2, root, allowed)).find(Boolean);
  if (!position) return null;
  const ruleId = raw.ident;
  const result2 = {
    tool: "zizmor",
    ruleId,
    ...position,
    severity: SEVERITY[raw.determinations?.severity] || "UNKNOWN",
    confidence: CONFIDENCE.has(raw.determinations?.confidence) ? raw.determinations.confidence.toLowerCase() : "unknown",
    title: TITLE[ruleId] || `GitHub Actions security finding (${ruleId})`,
    remediation: REMEDIATION[ruleId] || "Review this workflow or action against the rule documentation, make a scoped change, and verify intended workflow behavior.",
    documentationUrl: `https://docs.zizmor.sh/audits/#${ruleId}`,
    verification: "scanner_finding"
  };
  result2.id = createHash("sha256").update(JSON.stringify([result2.tool, ruleId, position.file, position.line])).digest("hex").slice(0, 32);
  return result2;
}
async function persist(reportPath, result2) {
  if (reportPath) await writeFile(reportPath, JSON.stringify(result2), { mode: 384 });
  return result2;
}
async function runZizmor({
  root,
  files,
  reportPath,
  execute = spawnSync,
  executable = "/usr/local/bin/zizmor",
  timeoutMs = 12e4
} = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root) || !Array.isArray(files) || files.length > 500 || files.some((file) => !validRelative(file)) || new Set(files).size !== files.length || reportPath !== void 0 && (typeof reportPath !== "string" || !path.isAbsolute(reportPath)) || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 12e4)
    throw new Error("Zizmor requires a staged absolute root and bounded relative file paths.");
  const selected2 = files.filter(isZizmorInput);
  const coverage = {
    eligibleFiles: selected2.length,
    offlineAuditsOnly: true,
    scope: "Supplied GitHub Actions workflows and action definitions only. Online action metadata, remote repository state and exploit verification are not assessed."
  };
  const result2 = (status, findings, error) => ({ status, version: ZIZMOR_VERSION, findings, coverage, ...error ? { error } : {} });
  if (!selected2.length) return persist(reportPath, result2("partial", [], "No GitHub Actions workflow or action definition was detected."));
  let actualRoot;
  try {
    actualRoot = await realpath(root);
    for (const relative of selected2) {
      const target = path.join(actualRoot, relative);
      const metadata = await lstat(target);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 256 * 1024 || await realpath(target) !== target) throw new Error("Unstaged input");
    }
  } catch {
    return persist(reportPath, result2("failed", [], "Workflow inputs must be regular staged files within the scan root."));
  }
  const work = await mkdtemp(path.join(os.tmpdir(), "purple-zizmor-"));
  try {
    let completed;
    try {
      completed = execute(executable, [
        "--offline",
        "--no-config",
        "--no-ignores",
        "--strict-collection",
        "--format=json-v1",
        "--persona=regular",
        "--no-progress",
        "--color=never",
        "--no-exit-codes",
        "--quiet",
        "--cache-dir",
        path.join(work, "cache"),
        "--",
        ...selected2.map((relative) => path.join(actualRoot, relative))
      ], {
        cwd: work,
        env: {
          PATH: "/usr/local/bin:/usr/bin:/bin",
          HOME: work,
          TMPDIR: work,
          XDG_CONFIG_HOME: work,
          XDG_CACHE_HOME: work,
          ZIZMOR_OFFLINE: "1",
          NO_COLOR: "1"
        },
        encoding: "utf8",
        timeout: timeoutMs,
        killSignal: "SIGKILL",
        maxBuffer: MAX_OUTPUT,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch {
      return persist(reportPath, result2("failed", [], "GitHub Actions scanner failed or timed out."));
    }
    if (!completed || completed.error || completed.signal || ![0, 1, 3].includes(completed.status))
      return persist(reportPath, result2("failed", [], "GitHub Actions scanner failed or timed out."));
    if (completed.status === 3) return persist(reportPath, result2("partial", [], "GitHub Actions scanner could not collect the selected inputs."));
    let raw;
    try {
      if (typeof completed.stdout !== "string" || Buffer.byteLength(completed.stdout) > MAX_OUTPUT) throw new Error("Report bounds");
      raw = JSON.parse(completed.stdout);
      if (!Array.isArray(raw) || raw.length > 5e3) throw new Error("Report shape");
    } catch {
      return persist(reportPath, result2(
        completed.status === 1 ? "partial" : "failed",
        [],
        completed.status === 1 ? "GitHub Actions inputs could not be fully parsed or audited." : "GitHub Actions scanner returned an invalid report."
      ));
    }
    const allowed = new Set(selected2);
    const findings = raw.map((item) => normalized(item, actualRoot, allowed)).filter(Boolean);
    const unique = [...new Map(findings.map((item) => [item.id, item])).values()];
    const incomplete = completed.status !== 0 || findings.length !== raw.length || findings.some((item) => item.severity === "UNKNOWN" || item.confidence === "unknown") || unique.length > MAX_FINDINGS;
    return persist(reportPath, result2(
      incomplete ? "partial" : "complete",
      unique.slice(0, MAX_FINDINGS),
      incomplete ? "GitHub Actions findings or input coverage were incomplete. Narrow the scan and review omitted inputs or findings." : void 0
    ));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

// agent/scan-findings.mjs
import { createHash as createHash2 } from "node:crypto";
var text = (value, max = 1e3) => typeof value === "string" ? value.slice(0, max) : "";
function location(value, root) {
  const name = text(value, 500).replaceAll("\\", "/");
  const relative = name.startsWith(`${root}/`) ? name.slice(root.length + 1) : name.replace(/^\.\//, "");
  if (!relative || relative.startsWith("/") || relative.split("/").some((part) => part === "..")) return null;
  return relative;
}
var severity = (value) => ({ ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW", CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW" })[String(value).toUpperCase()] || "UNKNOWN";
function normalizeFindings(tool, data, root = "/tmp/purple-scan/source", { inputPath } = {}) {
  const findings = [];
  function add(item) {
    const file = location(item.file, root);
    if (!file) return;
    const line = Number.isInteger(item.line) && item.line > 0 ? item.line : null;
    const result2 = {
      tool,
      ruleId: text(item.ruleId, 200),
      file,
      line,
      severity: severity(item.severity),
      title: text(item.title, 300),
      remediation: text(item.remediation, 1500),
      verification: "scanner_finding",
      ...item.package ? { package: text(item.package, 200), installedVersion: text(item.installedVersion, 100), fixedVersion: text(item.fixedVersion, 200) } : {}
    };
    result2.id = createHash2("sha256").update(JSON.stringify([tool, result2.ruleId, file, line, result2.package, result2.installedVersion])).digest("hex").slice(0, 32);
    findings.push(result2);
  }
  if (tool === "opengrep") for (const item of data.results || []) add({
    file: item.path,
    line: item.start?.line,
    // Opengrep can prefix IDs with the operator config's temporary directory.
    // Retain stable rule identity without persisting that local path.
    ruleId: typeof item.check_id === "string" ? item.check_id.match(/(?:^|\.)(purple\.(?:js|python)\.[a-z0-9-]+)$/)?.[1] || item.check_id : "",
    severity: item.extra?.severity,
    title: item.extra?.message,
    remediation: item.extra?.metadata?.remediation || "Review the flagged operation and validate untrusted inputs before using this API."
  });
  if (["trivy", "trivy-vuln", "trivy-sbom", "trivy-image"].includes(tool)) for (const target of data.Results || []) for (const item of target.Vulnerabilities || []) add({
    file: inputPath || target.Target,
    line: item.PkgIdentifier?.LineNumber,
    ruleId: item.VulnerabilityID,
    severity: item.Severity,
    title: item.Title || item.VulnerabilityID,
    package: item.PkgName,
    installedVersion: item.InstalledVersion,
    fixedVersion: item.FixedVersion,
    remediation: item.FixedVersion ? `Upgrade ${text(item.PkgName, 200)} to a fixed version: ${text(item.FixedVersion, 200)}. Verify compatibility and re-scan.` : "No fixed version reported. Assess exposure and apply a reviewed mitigation."
  });
  if (tool === "trivy-config") for (const target of data.Results || []) for (const item of target.Misconfigurations || []) {
    if (item.Status && String(item.Status).toUpperCase() !== "FAIL") continue;
    add({
      file: target.Target,
      line: item.CauseMetadata?.StartLine || item.CauseMetadata?.Code?.Lines?.[0]?.Number,
      ruleId: item.ID || item.AVDID,
      severity: item.Severity,
      title: item.Title || item.ID,
      remediation: item.Resolution || "Review this infrastructure setting against the rule and re-scan after changing it."
    });
  }
  if (tool === "gitleaks") for (const item of data) add({
    file: item.File,
    line: item.StartLine,
    ruleId: item.RuleID,
    severity: "HIGH",
    title: `Potential exposed credential (${text(item.RuleID, 100)})`,
    remediation: "Revoke and rotate this credential, remove it from source, and inspect its use. Removing the string alone does not revoke it."
  });
  return [...new Map(findings.map((item) => [item.id, item])).values()];
}

// scripts/skill-updater.mjs
import { constants } from "node:fs";
import { lstat as lstat2, mkdir, open, readFile, realpath as realpath2, rename, unlink } from "node:fs/promises";
import { createHash as createHash3, randomUUID } from "node:crypto";
import path2 from "node:path";
import { fileURLToPath } from "node:url";
var INSTALL_RECORD = ".skill-install.json";
var LOCK = ".skill-update.lock";
var JOURNAL = ".skill-update-transaction.json";
var PENDING = ".skill-update-pending.json";
var MAX_FILE = 2e6;
var MAX_TOTAL = 12e6;
var MAX_MANIFEST = 128e3;
var hash = (value) => createHash3("sha256").update(value).digest("hex");
var shaPattern = /^[a-f0-9]{64}$/;
var versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
var names = /* @__PURE__ */ new Set(["offense", "purple"]);
var NEW_SESSION_MESSAGE = "Start a new coding-agent session in this same project to load the updated skill.";
function managedPath(value) {
  return typeof value === "string" && !value.includes("\\") && !value.split("/").some((part) => !part || part.startsWith(".")) && (value === "SKILL.md" || /^(?:scripts\/[A-Za-z0-9_./-]+\.mjs|references\/[A-Za-z0-9_./-]+\.md|agents\/openai\.yaml)$/.test(value));
}
function relativePath(value) {
  return typeof value === "string" && value && !path2.isAbsolute(value) && !value.includes("\\") && !value.split("/").some((part) => !part || part === "." || part === "..");
}
function compareVersions(a, b) {
  const left = a.split(".").map(Number), right = b.split(".").map(Number);
  for (let index = 0; index < 3; index++) if (left[index] !== right[index]) return left[index] > right[index] ? 1 : -1;
  return 0;
}
function validateRelease(manifest, skill) {
  if (!names.has(skill) || manifest?.schemaVersion !== 1 || manifest.skill !== skill || !versionPattern.test(manifest.version || "") || !Number.isInteger(manifest.minimumNodeMajor) || manifest.minimumNodeMajor < 20 || manifest.minimumNodeMajor > 99 || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 32) throw Error("Unsupported skill release manifest.");
  const seen = /* @__PURE__ */ new Set();
  let total = 0;
  for (const file of manifest.files) {
    if (!managedPath(file.path) || seen.has(file.path.toLowerCase()) || !shaPattern.test(file.sha256 || "") || !Number.isInteger(file.bytes) || file.bytes < 0 || file.bytes > MAX_FILE) throw Error("Invalid or duplicate managed skill file.");
    seen.add(file.path.toLowerCase());
    total += file.bytes;
  }
  const entrypoint = skill === "offense" ? "scripts/offense.mjs" : "scripts/purple.mjs";
  if (!seen.has("skill.md") || !seen.has(entrypoint) || !seen.has("scripts/update.mjs") || !manifest.files.find((file) => file.path === "SKILL.md")?.bytes || total > MAX_TOTAL) throw Error("Incomplete or oversized skill release.");
  if (!Array.isArray(manifest.previousReleases) || manifest.previousReleases.length > 16) throw Error("Invalid skill release history.");
  for (const release of manifest.previousReleases) {
    if (!versionPattern.test(release?.version || "") || !release.files || typeof release.files !== "object" || Array.isArray(release.files) || Object.keys(release.files).length > 32 || Object.entries(release.files).some(([file, digest]) => !managedPath(file) || !shaPattern.test(digest))) throw Error("Invalid historical skill hashes.");
  }
  return manifest;
}
async function rootDirectory(root) {
  const resolved = path2.resolve(root), info = await lstat2(resolved);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath2(resolved) !== resolved) throw Error("Skill installation must be a real directory without symlink parents.");
  return resolved;
}
async function inside(root, relative, createParents = false) {
  if (!relativePath(relative)) throw Error("Invalid skill-local path.");
  const parts = relative.split("/");
  let current = root;
  for (const part of parts.slice(0, -1)) {
    current = path2.join(current, part);
    let info;
    try {
      info = await lstat2(current);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      if (!createParents) return null;
      try {
        await mkdir(current, { mode: 448 });
      } catch (created) {
        if (created.code !== "EEXIST") throw created;
      }
      info = await lstat2(current);
    }
    if (!info.isDirectory() || info.isSymbolicLink()) throw Error("Refusing a symlink or non-directory in the skill installation.");
  }
  return path2.join(root, ...parts);
}
async function localFile(root, relative, limit = MAX_FILE) {
  const filename = await inside(root, relative);
  if (!filename) return null;
  let handle;
  try {
    const info = await lstat2(filename);
    if (!info.isFile() || info.isSymbolicLink() || info.size > limit) throw Error("Refusing an unsafe or oversized skill file: " + relative);
    handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const actual = await handle.stat();
    if (!actual.isFile() || actual.size > limit) throw Error("Skill file changed while reading: " + relative);
    const bytes = await handle.readFile();
    if (bytes.length > limit) throw Error("Oversized skill file: " + relative);
    return { bytes, sha256: hash(bytes), mode: actual.mode & 511 };
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  } finally {
    await handle?.close();
  }
}
async function atomicFile(root, relative, bytes, mode = 384) {
  const filename = await inside(root, relative, true);
  await localFile(root, relative, relative === JOURNAL ? MAX_TOTAL * 2 : MAX_TOTAL);
  const temp = path2.join(path2.dirname(filename), ".purple-update-" + randomUUID());
  let handle;
  try {
    handle = await open(temp, "wx", mode);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await inside(root, relative);
    await localFile(root, relative, relative === JOURNAL ? MAX_TOTAL * 2 : MAX_TOTAL);
    await rename(temp, filename);
  } finally {
    await handle?.close();
    await unlink(temp).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}
async function removeLocal(root, relative) {
  if (!await localFile(root, relative, MAX_TOTAL * 2)) return;
  await unlink(await inside(root, relative));
}
function recordJson(file) {
  try {
    return file ? JSON.parse(file.bytes.toString("utf8")) : null;
  } catch {
    throw Error("Invalid local skill update record.");
  }
}
function validateRecord(record, skill) {
  if (record === null) return null;
  if (record.schemaVersion !== 1 || record.skill !== skill || !versionPattern.test(record.releaseVersion || "") || !record.files || Array.isArray(record.files) || typeof record.files !== "object" || Object.keys(record.files).length > 32 || Object.entries(record.files).some(([file, value]) => !managedPath(file) || !shaPattern.test(value?.upstreamSha256 || "") || !shaPattern.test(value?.localSha256 || "") || typeof value.customized !== "boolean")) throw Error("Invalid local skill installation receipt.");
  return record;
}
async function acquireLock(root) {
  const filename = await inside(root, LOCK);
  let handle;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      handle = await open(filename, "wx", 384);
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const bytes = await localFile(root, LOCK, 1024);
      if (!bytes) continue;
      let existing;
      try {
        existing = recordJson(bytes);
      } catch {
        return null;
      }
      if (!Number.isInteger(existing?.pid) || existing.pid < 1) return null;
      try {
        process.kill(existing.pid, 0);
        return null;
      } catch (probe) {
        if (probe.code !== "ESRCH") return null;
      }
      await removeLocal(root, LOCK);
    }
  }
  if (!handle) return null;
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid }));
  } catch (error) {
    await handle.close();
    await unlink(filename);
    throw error;
  }
  await handle.close();
  return () => removeLocal(root, LOCK);
}
async function boundedDownload(fetchImpl, url, limit, signal) {
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json, text/plain, */*", "cache-control": "no-cache" },
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    signal
  });
  if (!response.ok) throw Error("Skill release download returned HTTP " + response.status + ".");
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) throw Error("Skill release download exceeds its size limit.");
  if (!response.body) throw Error("Skill release download has no body.");
  const reader = response.body.getReader(), chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) throw Error("Skill release download exceeds its size limit.");
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {
    });
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}
async function snapshot(root, files) {
  const entries = await Promise.all(files.map(async (file) => [file.path, await localFile(root, file.path)]));
  if (entries.reduce((total, [, file]) => total + (file?.bytes.length || 0), 0) > MAX_TOTAL) throw Error("Installed skill exceeds its size limit.");
  return new Map(entries);
}
function installationRecord(skill, manifest, current) {
  return {
    schemaVersion: 1,
    skill,
    releaseVersion: manifest.version,
    files: Object.fromEntries(manifest.files.map((file) => [file.path, {
      upstreamSha256: file.sha256,
      localSha256: current.get(file.path).sha256,
      customized: current.get(file.path).sha256 !== file.sha256
    }]))
  };
}
function result(status, extra = {}) {
  return { status, sessionReloadRequired: false, stop: false, ...extra };
}
async function recoverTransaction(root, skill) {
  const journal = recordJson(await localFile(root, JOURNAL, MAX_TOTAL * 2));
  if (!journal) return;
  if (journal.schemaVersion !== 1 || journal.skill !== skill || !Array.isArray(journal.files) || journal.files.length > 32 || !shaPattern.test(journal.newReceiptSha256 || "") || journal.oldReceipt !== null && typeof journal.oldReceipt !== "string") throw Error("Invalid interrupted skill update.");
  const conflicts = [];
  for (const file of journal.files) {
    if (!managedPath(file.path) || !shaPattern.test(file.nextSha256 || "") || file.previous !== null && (typeof file.previous !== "string" || !shaPattern.test(file.previousSha256 || "")) || !Number.isInteger(file.mode) || file.mode < 0 || file.mode > 511) throw Error("Invalid interrupted skill file.");
    const previous = file.previous === null ? null : Buffer.from(file.previous, "base64");
    if (previous && (previous.length > MAX_FILE || hash(previous) !== file.previousSha256)) throw Error("Invalid skill recovery content.");
    const current = await localFile(root, file.path);
    if (current?.sha256 === file.previousSha256 || !current && !previous) continue;
    if (current?.sha256 !== file.nextSha256) {
      conflicts.push(file.path);
      continue;
    }
    if (previous) await atomicFile(root, file.path, previous, file.mode & 511);
    else await removeLocal(root, file.path);
  }
  const oldReceipt = journal.oldReceipt === null ? null : Buffer.from(journal.oldReceipt, "base64");
  if (oldReceipt) {
    if (oldReceipt.length > MAX_MANIFEST) throw Error("Invalid recovery receipt size.");
    validateRecord(recordJson({ bytes: oldReceipt }), skill);
  }
  const currentReceipt = await localFile(root, INSTALL_RECORD, MAX_MANIFEST);
  if (currentReceipt?.sha256 === journal.newReceiptSha256) {
    if (oldReceipt) await atomicFile(root, INSTALL_RECORD, oldReceipt);
    else await removeLocal(root, INSTALL_RECORD);
  } else if (currentReceipt?.sha256 !== (oldReceipt ? hash(oldReceipt) : void 0)) conflicts.push(INSTALL_RECORD);
  if (conflicts.length) throw Error("Interrupted update preserved concurrent edits; review staged files before accepting local changes: " + conflicts.join(", "));
  await removeLocal(root, JOURNAL);
}
async function checkSkillUpdates({ skill, root, automatic = false, mode = "auto", fetchImpl = fetch, beforeReplace } = {}) {
  let releaseLock, resolved, recoveryNeeded = false;
  try {
    if (!names.has(skill) || !["auto", "check", "accept-local"].includes(mode)) throw Error("Unknown skill or update mode.");
    resolved = await rootDirectory(root);
    const distributionFile = await localFile(resolved, ".offense-distribution.json");
    if (distributionFile) {
      const distribution = recordJson(distributionFile);
      if (distribution?.schemaVersion !== 1 || distribution.manager !== "codex-plugin") throw Error("Unknown skill distribution; preserve this installation and use its manager.");
      return result("plugin_managed", { message: "Codex manages this plugin. Update it through the Codex plugin manager, then start a new session. Hosted self-updates are disabled." });
    }
    if (path2.basename(path2.dirname(resolved)) === "skills" && path2.basename(path2.dirname(path2.dirname(resolved))) === "public" && await lstat2(path2.resolve(resolved, "../../..", ".git")).catch((error) => {
      if (error.code === "ENOENT") return null;
      throw error;
    })) {
      return result("not_installed", automatic ? {} : { message: "Run the updater from an installed skill copy, not the repository\u2019s published source assets." });
    }
    if (automatic && !await localFile(resolved, "SKILL.md")) return result("not_installed");
    releaseLock = await acquireLock(resolved);
    if (!releaseLock) return result("busy", { stop: true, message: "A skill update is running or its lock needs review. Retry after it finishes." });
    if (mode !== "accept-local") {
      recoveryNeeded = true;
      await recoverTransaction(resolved, skill);
      recoveryNeeded = false;
    }
    const origin = "https://app.purpleteam.sh/skills/" + skill + "/";
    const manifestBytes = await boundedDownload(fetchImpl, origin + "manifest.json", MAX_MANIFEST, AbortSignal.timeout(5e3));
    let manifest;
    try {
      manifest = validateRelease(JSON.parse(manifestBytes.toString("utf8")), skill);
    } catch {
      throw Error("Invalid or unsupported skill release manifest.");
    }
    if (Number(process.versions.node.split(".")[0]) < manifest.minimumNodeMajor) return result("runtime_required", { message: `Skill ${manifest.version} requires Node ${manifest.minimumNodeMajor}+. Existing installation was preserved.` });
    const receiptFile = await localFile(resolved, INSTALL_RECORD, MAX_MANIFEST), receipt = validateRecord(recordJson(receiptFile), skill);
    const current = await snapshot(resolved, manifest.files), digest = hash(manifestBytes);
    if (receipt?.releaseVersion === manifest.version && (Object.keys(receipt.files).length !== manifest.files.length || manifest.files.some((file) => receipt.files[file.path]?.upstreamSha256 !== file.sha256))) throw Error("Hosted skill files changed without a version bump; no update was applied.");
    const pending = mode === "accept-local" ? recordJson(await localFile(resolved, PENDING, MAX_MANIFEST)) : null;
    if (mode === "accept-local") {
      if (pending?.version !== manifest.version || pending?.manifestSha256 !== digest || pending?.skill !== skill || !relativePath(pending?.directory) || !/^\.skill-updates\/[A-Za-z0-9.-]+$/.test(pending.directory) || current.size !== manifest.files.length || [...current.values()].some((file) => !file)) throw Error("Review and merge a complete staged release before accepting local files.");
      const staged = await localFile(resolved, pending.directory + "/manifest.json", MAX_MANIFEST);
      if (staged?.sha256 !== digest) throw Error("Staged release identity changed; check for updates again.");
      await atomicFile(resolved, INSTALL_RECORD, Buffer.from(JSON.stringify(installationRecord(skill, manifest, current), null, 2) + "\n"));
      await removeLocal(resolved, JOURNAL);
      await removeLocal(resolved, PENDING);
      return result("customizations_accepted", {
        version: manifest.version,
        sessionReloadRequired: true,
        stop: true,
        message: "Local customizations recorded against release " + manifest.version + ". " + NEW_SESSION_MESSAGE
      });
    }
    const skillText = current.get("SKILL.md")?.bytes.toString("utf8") || "";
    const localVersion = receipt?.releaseVersion || skillText.match(/^---[\s\S]*?\n\s+version:\s*["']?([0-9]+\.[0-9]+\.[0-9]+)/)?.[1];
    if (localVersion && compareVersions(localVersion, manifest.version) > 0) return result("server_older", { version: localVersion, message: "The installed skill is newer than the hosted release; no downgrade was applied." });
    const retiredConflicts = [];
    for (const [file, base] of Object.entries(receipt?.files || {})) {
      if (current.has(file)) continue;
      const local = await localFile(resolved, file);
      if (local && (base.customized || local.sha256 !== base.upstreamSha256)) retiredConflicts.push(file);
    }
    const exact = manifest.files.every((file) => current.get(file.path)?.sha256 === file.sha256);
    if ((exact || receipt?.releaseVersion === manifest.version) && !retiredConflicts.length) {
      if (mode === "check") return result(exact ? "current" : "current_customized", { version: manifest.version });
      if (exact) {
        const changedRelease = receipt && receipt.releaseVersion !== manifest.version;
        const nextReceipt2 = Buffer.from(JSON.stringify(installationRecord(skill, manifest, current), null, 2) + "\n");
        if (!receiptFile?.bytes.equals(nextReceipt2)) await atomicFile(resolved, INSTALL_RECORD, nextReceipt2);
        if (await localFile(resolved, PENDING, MAX_MANIFEST)) await removeLocal(resolved, PENDING);
        return result(changedRelease ? "updated" : receipt ? "current" : "initialized", {
          version: manifest.version,
          sessionReloadRequired: Boolean(changedRelease),
          stop: Boolean(changedRelease),
          ...changedRelease ? { message: NEW_SESSION_MESSAGE } : {}
        });
      }
      return result("current_customized", { version: manifest.version, message: "Latest release is recorded; local customizations are preserved." });
    }
    const conflicts = [...retiredConflicts, ...manifest.files.filter((file) => {
      const local = current.get(file.path), base = receipt?.files[file.path];
      if (!local) return Boolean(base);
      if (local.sha256 === file.sha256) return false;
      if (base) return base.customized || local.sha256 !== base.upstreamSha256;
      return !manifest.previousReleases.some((release) => release.files[file.path] === local.sha256);
    }).map((file) => file.path)];
    if (mode === "check") return result("update_available", { version: manifest.version, conflicts });
    const downloads = /* @__PURE__ */ new Map(), signal = AbortSignal.timeout(3e4);
    for (const file of manifest.files) {
      const cached = current.get(file.path);
      const bytes = cached?.sha256 === file.sha256 ? cached.bytes : await boundedDownload(fetchImpl, origin + file.path, file.bytes, signal);
      if (bytes.length !== file.bytes || hash(bytes) !== file.sha256) throw Error("Skill release checksum mismatch: " + file.path);
      downloads.set(file.path, bytes);
    }
    const stage = ".skill-updates/" + manifest.version + "-" + digest.slice(0, 16);
    for (const file of manifest.files) {
      const existing = await localFile(resolved, stage + "/files/" + file.path);
      if (existing && existing.sha256 !== file.sha256) throw Error("Staged release was customized; preserve it and move it aside before retrying.");
      if (!existing) await atomicFile(resolved, stage + "/files/" + file.path, downloads.get(file.path));
    }
    const oldManifest = await localFile(resolved, stage + "/manifest.json", MAX_MANIFEST);
    if (oldManifest && oldManifest.sha256 !== digest) throw Error("Staged release manifest was customized; preserve it before retrying.");
    if (!oldManifest) await atomicFile(resolved, stage + "/manifest.json", manifestBytes);
    await atomicFile(resolved, PENDING, Buffer.from(JSON.stringify({ skill, version: manifest.version, manifestSha256: digest, directory: stage }, null, 2) + "\n"));
    const latest = await snapshot(resolved, manifest.files);
    for (const file of manifest.files) if (latest.get(file.path)?.sha256 !== current.get(file.path)?.sha256 && !conflicts.includes(file.path)) conflicts.push(file.path);
    if (conflicts.length) return result("review_required", {
      version: manifest.version,
      conflicts,
      stagedDirectory: path2.join(resolved, stage),
      message: "Update " + manifest.version + " is staged for review. Customized files were preserved: " + conflicts.join(", ") + ". Merge the reviewed files, then run update --accept-local."
    });
    const next = new Map(manifest.files.map((file) => [file.path, { sha256: file.sha256 }]));
    const nextReceipt = Buffer.from(JSON.stringify(installationRecord(skill, manifest, next), null, 2) + "\n");
    const changed = manifest.files.filter((file) => current.get(file.path)?.sha256 !== file.sha256);
    const journal = {
      schemaVersion: 1,
      skill,
      oldReceipt: receiptFile?.bytes.toString("base64") ?? null,
      newReceiptSha256: hash(nextReceipt),
      files: changed.map((file) => ({
        path: file.path,
        previous: current.get(file.path)?.bytes.toString("base64") ?? null,
        previousSha256: current.get(file.path)?.sha256 ?? null,
        nextSha256: file.sha256,
        mode: current.get(file.path)?.mode ?? 420
      }))
    };
    await atomicFile(resolved, JOURNAL, Buffer.from(JSON.stringify(journal)));
    try {
      for (const file of changed) {
        await beforeReplace?.(file.path);
        if ((await localFile(resolved, file.path))?.sha256 !== current.get(file.path)?.sha256) throw Error("Skill file changed before update: " + file.path);
        await atomicFile(resolved, file.path, downloads.get(file.path), current.get(file.path)?.mode ?? 420);
      }
      await atomicFile(resolved, INSTALL_RECORD, nextReceipt);
      await removeLocal(resolved, PENDING);
      await removeLocal(resolved, JOURNAL);
    } catch (error) {
      recoveryNeeded = true;
      await recoverTransaction(resolved, skill);
      recoveryNeeded = false;
      throw error;
    }
    return result("updated", {
      version: manifest.version,
      updatedFiles: changed.map((file) => file.path),
      sessionReloadRequired: true,
      stop: true,
      message: "Skill updated to " + manifest.version + ". " + NEW_SESSION_MESSAGE
    });
  } catch (error) {
    return result(recoveryNeeded ? "recovery_required" : "check_failed", {
      stop: recoveryNeeded,
      message: (recoveryNeeded ? "Skill update recovery needs review: " : "Could not update the skill; existing files were preserved: ") + error.message
    });
  } finally {
    await releaseLock?.();
  }
}
async function updateBeforeRun(skill, scriptUrl, { preview = false, fetchImpl = fetch, log = console.error } = {}) {
  if (preview) return result("offline_preview");
  const root = path2.resolve(path2.dirname(fileURLToPath(scriptUrl)), "..");
  const outcome = await checkSkillUpdates({ skill, root, automatic: true, fetchImpl });
  if (outcome.message) log("Skill updates: " + outcome.message);
  if (outcome.stop) process.exitCode = outcome.sessionReloadRequired ? 4 : 3;
  return outcome;
}

// scripts/source-scan-client.mjs
var VERSIONS = { opengrep: "1.32.0", zizmor: "1.31.1" };
var SKIP = /* @__PURE__ */ new Set(["node_modules", ".git", ".agents", ".codex", ".claude", ".pi", "dist", "build", "coverage", ".next", ".venv", "venv"]);
var environment = (root) => ({
  PATH: "/usr/local/bin:/usr/bin:/bin",
  HOME: root,
  TMPDIR: root,
  SEMGREP_SEND_METRICS: "off",
  SEMGREP_ENABLE_VERSION_CHECK: "0",
  NO_COLOR: "1",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0"
});
var selected = (tools) => {
  const value = tools ?? ["opengrep", "zizmor"];
  if (!Array.isArray(value) || !value.length || new Set(value).size !== value.length || value.some((tool) => !Object.hasOwn(VERSIONS, tool)))
    throw Error("Select opengrep or zizmor with --tool.");
  return value;
};
var relevant = (name, tools) => tools.includes("opengrep") && /\.(?:[cm]?jsx?|tsx?|py)$/i.test(name) || tools.includes("zizmor") && (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(name) || /(?:^|\/)action\.ya?ml$/i.test(name));
async function collectLocalSource(directory, tools = ["opengrep", "zizmor"]) {
  const root = await noSymlinkDirectory(path3.resolve(directory));
  let names2;
  try {
    names2 = execFileSync("git", [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "core.hooksPath=/dev/null",
      "ls-files",
      "--cached",
      "-z",
      "--",
      "."
    ], {
      cwd: root,
      env: environment(os2.tmpdir()),
      maxBuffer: 4 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 1e4
    }).toString("utf8").split("\0").filter(Boolean);
  } catch {
    throw Error("A local Git checkout and Git CLI are required. No source was sent.");
  }
  const files = [], omitted = [];
  let bytes = 0;
  for (const name of [...new Set(names2)]) {
    if (name.startsWith("/") || name.includes("\\") || name.split("/").some((part) => !part || part === "." || part === ".."))
      throw Error("A tracked path is unsafe.");
    if (name.split("/").some((part) => SKIP.has(part)) || !relevant(name, tools)) {
      omitted.push({ path: name, reason: "outside_supported_source_scope" });
      continue;
    }
    const target = path3.join(root, name);
    let current = root, info;
    for (const part of name.split("/")) {
      current = path3.join(current, part);
      info = await lstat3(current).catch(() => null);
      if (!info || info.isSymbolicLink()) {
        info = null;
        break;
      }
    }
    if (!info?.isFile()) {
      omitted.push({ path: name, reason: "missing_symlink_or_non_file" });
      continue;
    }
    if (info.size > 256 * 1024 || files.length >= 500) throw Error("Local scan exceeds the file budget. Narrow the scan directory.");
    const buffer = await readFile2(target);
    if (buffer.length > 256 * 1024 || (bytes += buffer.length) > 4 * 1024 * 1024) throw Error("Local scan exceeds the source byte budget.");
    let content;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
      omitted.push({ path: name, reason: "non_utf8" });
      continue;
    }
    if (content.includes("\0")) {
      omitted.push({ path: name, reason: "binary" });
      continue;
    }
    files.push({ path: name, content });
  }
  return { files, omitted, bytes, scope: "Tracked supported files at their current working versions. Untracked files, generated output and dependency/agent directories are excluded." };
}
async function noSymlinkDirectory(directory, { create = false } = {}) {
  let current = path3.parse(directory).root;
  for (const part of directory.slice(current.length).split(path3.sep).filter(Boolean)) {
    current = path3.join(current, part);
    if (create) await mkdir2(current, { mode: 448 }).catch((error) => {
      if (error.code !== "EEXIST") throw error;
    });
    const info = await lstat3(current);
    if (info.isSymbolicLink() || !info.isDirectory()) throw Error("Scan directories must not contain symlinks or non-directories.");
  }
  return directory;
}
async function savePrivate(directory, filename, content) {
  const target = path3.join(directory, filename), info = await lstat3(target).catch(() => null);
  if (info && (info.isSymbolicLink() || !info.isFile())) throw Error("A report target is not a regular file.");
  const temporary = path3.join(directory, `.${filename}-${process.pid}-${Date.now()}`);
  try {
    await writeFile2(temporary, content, { mode: 384, flag: "wx" });
    await rename2(temporary, target);
  } finally {
    await rm2(temporary, { force: true });
  }
}
async function localSourceScan(directory, {
  tools,
  output,
  preview = false,
  execute = spawnSync2,
  collect = collectLocalSource,
  opengrep = "opengrep",
  zizmor = "zizmor",
  rulesPath
} = {}) {
  const chosen = selected(tools), source = await collect(path3.resolve(directory), chosen);
  if (preview) return {
    tools: chosen,
    files: source.files.map((file) => file.path),
    omitted: source.omitted,
    sourceBytes: source.bytes,
    sourceUpload: false,
    executesApplication: false
  };
  const temporary = await mkdtemp2(path3.join(os2.tmpdir(), "purple-source-"));
  const root = path3.join(temporary, "source");
  await mkdir2(root, { mode: 448 });
  const results = [], findings = [];
  try {
    if (!rulesPath) {
      rulesPath = path3.join(temporary, "operator-rules.yml");
      const rules = true ? `rules:
  - id: purple.js.dynamic-eval
    languages: [javascript, typescript]
    severity: WARNING
    message: Dynamic evaluation can execute attacker-controlled code.
    metadata:
      remediation: Remove dynamic code evaluation. Use a data parser or an explicit allowlist of operations.
    patterns:
      - pattern-either:
          - pattern: eval($X)
          - pattern: new Function(...)
      - pattern-not: eval("...")
  - id: purple.js.shell-exec
    languages: [javascript, typescript]
    severity: WARNING
    message: Shell command execution needs review for attacker-controlled input.
    metadata:
      remediation: Prefer execFile or spawn with a fixed executable and argument array; validate every untrusted argument.
    pattern-either:
      - pattern: require('child_process').exec(...)
      - pattern: require('node:child_process').exec(...)
      - pattern: |
          import {exec as $EXEC} from 'child_process';
          ...
          $EXEC(...)
      - pattern: |
          import {exec as $EXEC} from 'node:child_process';
          ...
          $EXEC(...)
  - id: purple.python.shell-execution
    languages: [python]
    severity: WARNING
    message: Shell execution can expose command injection.
    metadata:
      remediation: Use an argument array with shell=False and validate attacker-controlled arguments.
    pattern-either:
      - pattern: os.system($X)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
  - id: purple.python.unsafe-deserialization
    languages: [python]
    severity: WARNING
    message: Pickle deserialization can execute code when input is untrusted.
    metadata:
      remediation: Use a safe data format for untrusted input; do not deserialize attacker-supplied pickle data.
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
  - id: purple.js.tls-verification-disabled
    languages: [javascript, typescript]
    severity: ERROR
    message: TLS certificate verification is disabled.
    metadata:
      remediation: Enable certificate verification and configure the correct trusted CA certificate.
    pattern: 'rejectUnauthorized: false'

  # These rules model request-to-sink flow within the current file. They are
  # candidates for source review and regression tests, never exploit proof.
  # Do not add generic sanitizers: parsing a URL, normalizing a path, or naming
  # a helper "sanitize" does not establish a security boundary.
  - id: purple.js.request-sql-injection
    languages: [javascript, typescript]
    mode: taint
    severity: ERROR
    message: Request data reaches a SQL statement rather than a bound parameter.
    metadata:
      cwe: CWE-89
      coverage: Express and Hono request data to common SQL query APIs; within-file analysis only.
      remediation: Keep SQL statements constant and bind request values with the database driver's parameter API. Review dynamic identifiers against a fixed allowlist, then add an injection regression test and normal query tests.
    pattern-sources: &js-http-sources
      - patterns:
          - pattern-either:
              - pattern: $REQ.query
              - pattern: $REQ.params
              - pattern: $REQ.body
              - pattern: $REQ.cookies
              - pattern: $REQ.get(...)
              - pattern: $REQ.header(...)
              - pattern: $REQ.headers
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
        exact: true
      - patterns:
          - pattern-either:
              - pattern: $CTX.req.query(...)
              - pattern: $CTX.req.param(...)
              - pattern: $CTX.req.json(...)
              - pattern: $CTX.req.text(...)
              - pattern: $CTX.req.header(...)
          - metavariable-regex:
              metavariable: $CTX
              regex: ^(c|ctx|context)$
        exact: true
      - patterns:
          - pattern-either:
              - pattern: $REQ.nextUrl.searchParams.get(...)
              - pattern: new URL($REQ.url).searchParams.get(...)
              - pattern: $REQ.json(...)
              - pattern: $REQ.text(...)
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
        exact: true
    pattern-sanitizers:
      - pattern: Number(...)
        exact: true
      - pattern: parseInt(...)
        exact: true
      - pattern: Number.parseInt(...)
        exact: true
      - pattern: parseFloat(...)
        exact: true
      - pattern: Number.parseFloat(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $DB.query($SQL, ...)
              - pattern: $DB.execute($SQL, ...)
          - pattern-not: '$DB.query({text: $TEXT, ...}, ...)'
          - pattern-not: '$DB.query({sql: $TEXT, ...}, ...)'
          - pattern-not: '$DB.execute({sql: $TEXT, ...}, ...)'
          - metavariable-regex:
              metavariable: $DB
              regex: ^(db|database|client|pool|connection|conn|cursor|manager)$
          - focus-metavariable: $SQL
      - patterns:
          - pattern-either:
              - pattern: '$DB.query({text: $SQL, ...}, ...)'
              - pattern: '$DB.query({sql: $SQL, ...}, ...)'
              - pattern: '$DB.execute({sql: $SQL, ...}, ...)'
          - metavariable-regex:
              metavariable: $DB
              regex: ^(db|database|client|pool|connection|conn|cursor|manager)$
          - focus-metavariable: $SQL
      - patterns:
          - pattern-either:
              - pattern: $PRISMA.$queryRawUnsafe($SQL, ...)
              - pattern: $PRISMA.$executeRawUnsafe($SQL, ...)
          - focus-metavariable: $SQL

  - id: purple.js.request-command-injection
    languages: [javascript, typescript]
    mode: taint
    severity: ERROR
    message: Request data reaches a shell command.
    metadata:
      cwe: CWE-78
      coverage: Express and Hono request data to Node child_process shell execution; within-file analysis only.
      remediation: Replace shell command strings with execFile or spawn using a fixed executable, shell disabled, and an argument array. Validate arguments and add security and normal-behavior regression tests.
    pattern-sources: *js-http-sources
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: require('child_process').exec($COMMAND, ...)
              - pattern: require('node:child_process').exec($COMMAND, ...)
              - pattern: require('child_process').execSync($COMMAND, ...)
              - pattern: require('node:child_process').execSync($COMMAND, ...)
          - focus-metavariable: $COMMAND
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  import {exec as $EXEC} from 'child_process';
                  ...
              - pattern-inside: |
                  import {exec as $EXEC} from 'node:child_process';
                  ...
              - pattern-inside: |
                  import {execSync as $EXEC} from 'child_process';
                  ...
              - pattern-inside: |
                  import {execSync as $EXEC} from 'node:child_process';
                  ...
          - pattern: $EXEC($COMMAND, ...)
          - focus-metavariable: $COMMAND
      - patterns:
          - pattern-either:
              - pattern: $CP.exec($COMMAND, ...)
              - pattern: $CP.execSync($COMMAND, ...)
          - metavariable-regex:
              metavariable: $CP
              regex: ^(cp|childProcess|child_process)$
          - focus-metavariable: $COMMAND

  - id: purple.js.request-path-traversal
    languages: [javascript, typescript]
    mode: taint
    severity: ERROR
    message: Request data controls a filesystem read path.
    metadata:
      cwe: CWE-22
      coverage: Express and Hono request data to Node filesystem reads and one-argument Express sendFile; within-file analysis only.
      remediation: Resolve requested resources through a fixed allowlist or enforce canonical-path containment in the intended directory, including symlink behavior. Path normalization alone is insufficient. Add traversal and normal resource-read tests.
    pattern-sources: *js-http-sources
    pattern-sanitizers:
      - pattern: Number(...)
        exact: true
      - pattern: parseInt(...)
        exact: true
      - pattern: Number.parseInt(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $FS.readFile($FILE, ...)
              - pattern: $FS.readFileSync($FILE, ...)
              - pattern: $FS.createReadStream($FILE, ...)
              - pattern: $FS.promises.readFile($FILE, ...)
          - metavariable-regex:
              metavariable: $FS
              regex: ^(fs|fsp|fsPromises)$
          - focus-metavariable: $FILE
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  import {readFile as $READ} from 'fs';
                  ...
              - pattern-inside: |
                  import {readFile as $READ} from 'node:fs';
                  ...
              - pattern-inside: |
                  import {readFile as $READ} from 'fs/promises';
                  ...
              - pattern-inside: |
                  import {readFile as $READ} from 'node:fs/promises';
                  ...
          - pattern: $READ($FILE, ...)
          - focus-metavariable: $FILE
      - patterns:
          - pattern: $RES.sendFile($FILE)
          - metavariable-regex:
              metavariable: $RES
              regex: ^(res|response)$
          - focus-metavariable: $FILE

  - id: purple.js.request-ssrf
    languages: [javascript, typescript]
    mode: taint
    severity: ERROR
    message: Request data controls an outbound HTTP destination.
    metadata:
      cwe: CWE-918
      coverage: Express, Hono and selected Next.js request data to fetch and common Node HTTP clients; within-file analysis only.
      remediation: Use a fixed destination or an explicit destination policy enforced on every connection and redirect. Reject internal and link-local addresses and account for DNS changes. Add an SSRF regression test and normal outbound-request tests.
    pattern-sources: *js-http-sources
    pattern-sinks:
      - patterns:
          - pattern: fetch($URL, ...)
          - focus-metavariable: $URL
      - patterns:
          - pattern-either:
              - pattern: $HTTP.get($URL, ...)
              - pattern: $HTTP.post($URL, ...)
              - pattern: $HTTP.put($URL, ...)
              - pattern: $HTTP.request($URL, ...)
          - metavariable-regex:
              metavariable: $HTTP
              regex: ^(axios|got|http|https)$
          - focus-metavariable: $URL
      - patterns:
          - pattern-either:
              - pattern: axios($URL, ...)
              - pattern: got($URL, ...)
          - focus-metavariable: $URL

  - id: purple.python.request-sql-injection
    languages: [python]
    mode: taint
    severity: ERROR
    message: Request data reaches a SQL statement rather than a bound parameter.
    metadata:
      cwe: CWE-89
      coverage: Flask and Django request data to DB-API SQL execution and Django raw queries; within-file analysis only.
      remediation: Keep query text constant and pass values separately through bound parameters. Review dynamic identifiers against a fixed allowlist, then add an injection regression test and normal query tests.
    pattern-sources: &python-http-sources
      - patterns:
          - pattern-either:
              - pattern: $REQ.args
              - pattern: $REQ.form
              - pattern: $REQ.values
              - pattern: $REQ.json
              - pattern: $REQ.get_json(...)
              - pattern: $REQ.GET
              - pattern: $REQ.POST
              - pattern: $REQ.body
              - pattern: $REQ.query_params
              - pattern: $REQ.cookies
              - pattern: $REQ.headers
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
        exact: true
    pattern-sanitizers:
      - pattern: int(...)
        exact: true
      - pattern: float(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $CURSOR.execute($SQL, ...)
              - pattern: $CURSOR.executemany($SQL, ...)
          - focus-metavariable: $SQL
      - patterns:
          - pattern: $MODEL.objects.raw($SQL, ...)
          - focus-metavariable: $SQL

  - id: purple.python.request-command-injection
    languages: [python]
    mode: taint
    severity: ERROR
    message: Request data reaches a shell command.
    metadata:
      cwe: CWE-78
      coverage: Flask and Django request data to os, subprocess and asyncio shell execution; within-file analysis only.
      remediation: Use subprocess with a fixed executable, an argument list, and shell=False. Validate arguments and add security and normal-behavior regression tests.
    pattern-sources: *python-http-sources
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: os.system($COMMAND)
              - pattern: os.popen($COMMAND, ...)
              - pattern: subprocess.run($COMMAND, ..., shell=True, ...)
              - pattern: subprocess.Popen($COMMAND, ..., shell=True, ...)
              - pattern: subprocess.call($COMMAND, ..., shell=True, ...)
              - pattern: subprocess.check_call($COMMAND, ..., shell=True, ...)
              - pattern: subprocess.check_output($COMMAND, ..., shell=True, ...)
              - pattern: asyncio.create_subprocess_shell($COMMAND, ...)
          - focus-metavariable: $COMMAND

  - id: purple.python.request-path-traversal
    languages: [python]
    mode: taint
    severity: ERROR
    message: Request data controls a filesystem read path.
    metadata:
      cwe: CWE-22
      coverage: Flask and Django request data to file reads and Flask send_file; within-file analysis only.
      remediation: Prefer a fixed resource allowlist or a framework containment API such as send_from_directory. Enforce canonical-path containment and account for symlinks. Add traversal and normal resource-read regression tests.
    pattern-sources: *python-http-sources
    pattern-sanitizers:
      - pattern: int(...)
        exact: true
      - pattern: werkzeug.utils.secure_filename(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: open($FILE, ...)
              - pattern: pathlib.Path($FILE).read_text(...)
              - pattern: pathlib.Path($FILE).read_bytes(...)
              - pattern: Path($FILE).read_text(...)
              - pattern: Path($FILE).read_bytes(...)
              - pattern: flask.send_file($FILE, ...)
              - pattern: send_file($FILE, ...)
          - focus-metavariable: $FILE

  - id: purple.python.request-ssrf
    languages: [python]
    mode: taint
    severity: ERROR
    message: Request data controls an outbound HTTP destination.
    metadata:
      cwe: CWE-918
      coverage: Flask and Django request data to requests, httpx and urllib HTTP clients; within-file analysis only.
      remediation: Use fixed destinations or enforce a destination allowlist on every connection and redirect. Reject internal and link-local addresses and account for DNS changes. Add an SSRF regression test and normal outbound-request tests.
    pattern-sources: *python-http-sources
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: requests.get($URL, ...)
              - pattern: requests.post($URL, ...)
              - pattern: requests.put($URL, ...)
              - pattern: requests.request($METHOD, $URL, ...)
              - pattern: httpx.get($URL, ...)
              - pattern: httpx.post($URL, ...)
              - pattern: httpx.put($URL, ...)
              - pattern: httpx.request($METHOD, $URL, ...)
              - pattern: urllib.request.urlopen($URL, ...)
          - focus-metavariable: $URL
` : await readFile2(new URL("../agent/scan-rules.yml", import.meta.url), "utf8");
      await writeFile2(rulesPath, rules, { mode: 384, flag: "wx" });
    }
    for (const file of source.files) {
      if (file.path.startsWith("/") || file.path.split("/").some((part) => !part || part === "." || part === "..") || file.path.includes("\\")) throw Error("Unsafe source path.");
      const target2 = path3.join(root, file.path);
      await mkdir2(path3.dirname(target2), { recursive: true, mode: 448 });
      await writeFile2(target2, file.content, { mode: 384, flag: "wx" });
    }
    for (const tool of chosen) {
      const executable = tool === "opengrep" ? opengrep : zizmor, started = Date.now();
      const probe = execute(executable, ["--version"], { cwd: temporary, env: environment(temporary), timeout: 1e4, maxBuffer: 64e3, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      const versionPattern2 = new RegExp(`(?:^|\\s)${VERSIONS[tool].replaceAll(".", "\\.")}($|\\s)`);
      if (probe.error || probe.status !== 0 || !versionPattern2.test(String(probe.stdout || ""))) {
        results.push({ name: tool, version: VERSIONS[tool], status: "failed", error: "pinned_tool_unavailable", findings: 0 });
        continue;
      }
      if (tool === "zizmor") {
        const result2 = await runZizmor({
          root,
          files: source.files.map((file) => file.path),
          executable,
          execute,
          reportPath: path3.join(temporary, "zizmor.json"),
          timeoutMs: 12e4
        });
        findings.push(...result2.findings || []);
        results.push({
          name: tool,
          version: result2.version,
          status: result2.status,
          durationMs: Date.now() - started,
          findings: result2.findings?.length || 0,
          coverage: result2.coverage,
          ...result2.error ? { error: "workflow_scan_incomplete" } : {}
        });
      } else {
        if (!source.files.some((file) => /\.(?:[cm]?jsx?|tsx?|py)$/i.test(file.path))) {
          results.push({ name: tool, version: VERSIONS[tool], status: "partial", findings: 0, error: "no_supported_source" });
          continue;
        }
        const destination = path3.join(temporary, "opengrep.json");
        const run = execute(executable, [
          "scan",
          "--config",
          rulesPath,
          "--taint-intrafile",
          "--json",
          "--output",
          destination,
          "--disable-version-check",
          "--no-git-ignore",
          "--x-ignore-semgrepignore-files",
          "--disable-nosem",
          "--jobs",
          "2",
          "--timeout",
          "10",
          "--max-memory",
          "512",
          root
        ], {
          cwd: temporary,
          env: environment(temporary),
          timeout: 18e4,
          killSignal: "SIGKILL",
          maxBuffer: 1024 * 1024,
          stdio: ["ignore", "ignore", "ignore"]
        });
        let data;
        try {
          if ((await lstat3(destination)).size > 8 * 1024 * 1024) throw Error();
          data = JSON.parse(await readFile2(destination, "utf8"));
          if (!Array.isArray(data.results)) throw Error();
        } catch {
          results.push({ name: tool, version: VERSIONS[tool], status: "failed", findings: 0, error: "invalid_scanner_report" });
          continue;
        }
        const allowed = new Set(source.files.map((file) => file.path));
        const normalized2 = normalizeFindings(tool, data, root).filter((finding) => allowed.has(finding.file));
        const incomplete = run.error || run.status !== 0 || data.errors?.length;
        findings.push(...normalized2);
        results.push({
          name: tool,
          version: VERSIONS[tool],
          status: incomplete ? "partial" : "complete",
          durationMs: Date.now() - started,
          findings: normalized2.length,
          ...incomplete ? { error: "source_scan_incomplete" } : {}
        });
      }
    }
    const truncated = findings.length > 500;
    const incompleteSource = source.omitted.some((file) => file.reason !== "outside_supported_source_scope");
    const report = {
      schemaVersion: "purple.source-scan.v1",
      status: !truncated && !incompleteSource && results.every((tool) => tool.status === "complete") ? "completed" : results.every((tool) => tool.status === "failed") ? "failed" : "partial",
      tools: results,
      findings: findings.slice(0, 500),
      confirmedVulnerabilities: 0,
      sourceUpload: false,
      executesApplication: false,
      coverage: {
        sourceFiles: source.files.length,
        sourceBytes: source.bytes,
        omitted: source.omitted,
        scope: source.scope,
        analysis: "Operator rules and supported within-file input flow only. Scanner findings require source review and security regression evidence; no exploit or cross-file proof.",
        truncated,
        incompleteSource
      }
    };
    const requested = output && path3.resolve(output);
    if (requested && (requested === path3.resolve(directory) || requested.startsWith(path3.resolve(directory) + path3.sep))) throw Error("Choose a report directory outside the scanned checkout.");
    const target = requested ? await noSymlinkDirectory(requested, { create: true }) : await mkdtemp2(path3.join(os2.tmpdir(), "purple-source-report-"));
    await savePrivate(target, "scan.json", JSON.stringify(report, null, 2) + "\n");
    await savePrivate(target, "scan.md", `# Purple local source scan

Status: ${report.status}
Source uploaded: no
Confirmed vulnerabilities: 0

${report.tools.map((tool) => `${tool.name} ${tool.version}: ${tool.status}${tool.error ? ` (${tool.error})` : ""}`).join("\n\n")}

${report.findings.map((finding) => `- **${finding.severity}** ${finding.title} \u2014 ${finding.file}:${finding.line || "?"}
  ${finding.remediation}`).join("\n")}

${report.coverage.analysis}
`);
    return {
      status: report.status,
      findings: report.findings.length,
      confirmedVulnerabilities: 0,
      sourceUpload: false,
      report: path3.join(target, "scan.md"),
      json: path3.join(target, "scan.json")
    };
  } finally {
    await rm2(temporary, { recursive: true, force: true });
  }
}
async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log("Usage: node source-scan.mjs [checkout] [--tool opengrep|zizmor ...] [--preview] [--output directory] [--opengrep /path/to/binary] [--zizmor /path/to/binary]\nPinned tools: Opengrep 1.32.0, Zizmor 1.31.1. Install with your existing tool manager; no automatic installs, source uploads or application execution. Reports stay local.");
    return;
  }
  const directory = args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd(), options = {};
  while (args.length) {
    const option = args.shift();
    if (option === "--preview") options.preview = true;
    else if (["--tool", "--output", "--opengrep", "--zizmor"].includes(option) && args[0] && !args[0].startsWith("--")) {
      const value = args.shift();
      if (option === "--tool") (options.tools ||= []).push(value);
      else options[option.slice(2)] = value;
    } else throw Error("Unknown or incomplete source scan option.");
  }
  const update = await updateBeforeRun("purple", import.meta.url, { preview: options.preview });
  if (update.stop) return;
  const result2 = await localSourceScan(directory, options);
  console.log(JSON.stringify(result2, null, 2));
  if (!options.preview && result2.status !== "completed") process.exitCode = 2;
}
if (process.argv[1] && path3.resolve(process.argv[1]) === fileURLToPath2(import.meta.url)) main().catch(() => {
  console.error("Local source scan failed. Check checkout, pinned tools, budgets and report directory; no clean scan is implied. No source was uploaded.");
  process.exitCode = 1;
});
export {
  collectLocalSource,
  localSourceScan
};
