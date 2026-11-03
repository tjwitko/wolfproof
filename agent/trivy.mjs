// Trivy, against a container image the pipeline built. Opt-in: it runs only for `--trivy-image=<ref>`
// (the Action's `trivy-image` input), because the image is not in the project -- a pipeline builds
// it -- and the scan downloads a vulnerability database of about 140 MB.
//
// The dockerfile check reads the Dockerfile: whether the base image is past its end of life. It
// cannot see the packages inside the built image, and this does: the OS packages and the language
// packages Trivy finds in the image's layers.
//
// The gate runs Trivy itself rather than reading a report the pipeline wrote, for two reasons found
// scanning real images. Some of what decides the verdict is only in Trivy's log: on Kali, Trivy says
// "This OS version is not on the EOL list" on stderr and reports 0 vulnerabilities in 79 packages,
// because no Debian release in its database is called kali-rolling, and the JSON alone reads as
// clean. And a report written before the gate ran is a file someone could have written by hand.
//
// What blocks: a vulnerability at the chosen severity or above (HIGH by default) that has a fixed
// version, because then there is something to do -- upgrade the package or the base image. One with
// no fix yet, or below the severity, is counted in an advisory.

import { spawnSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import os from "os";
import path from "path";

import { setting } from "../lib/settings.mjs";

export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const DEFAULT_SEVERITY = "HIGH";

// Pulling the image and downloading the database are both in this, as well as the scan.
const TIMEOUT_MS = 15 * 60 * 1000;
const SHOWN = 5;

// Trivy reads settings from TRIVY_* variables, and some of them decide what is reported:
// TRIVY_SEVERITY, TRIVY_IGNORE_UNFIXED, TRIVY_IGNOREFILE, TRIVY_SKIP_FILES. Only the ones that say
// how to reach the image and the database are passed on: registry credentials, mirrors, the cache,
// and the transport. Every other one is dropped, and the run says which.
const KEPT_TRIVY_ENV = new Set([
  "TRIVY_USERNAME",
  "TRIVY_PASSWORD",
  "TRIVY_REGISTRY_TOKEN",
  "TRIVY_DB_REPOSITORY",
  "TRIVY_JAVA_DB_REPOSITORY",
  "TRIVY_CACHE_DIR",
  "TRIVY_INSECURE",
  "TRIVY_NON_SSL",
  "TRIVY_PLATFORM",
  "TRIVY_IMAGE_SRC",
  "TRIVY_DOCKER_HOST",
  "TRIVY_PODMAN_HOST",
  "TRIVY_TIMEOUT",
]);

// Warnings that change nothing about the result. The end-of-service-life ones are read from the
// report's EOSL flag instead, and "not on the EOL list" is judged with the report below.
const NOTHING_TO_ADD = [
  /^Using severities from other vendors/,
  /^This OS version is no longer supported by the distribution/,
  /^The vulnerability detection may be insufficient because security updates are not provided/,
  /^This OS version is not on the EOL list/,
];

/** The environment Trivy runs with, and the TRIVY_* variables left out of it. */
export function trivyEnv(env) {
  const kept = {};
  const dropped = [];
  for (const [k, v] of Object.entries(env)) {
    if (!k.startsWith("TRIVY_")) kept[k] = v;
    else if (KEPT_TRIVY_ENV.has(k)) kept[k] = v;
    else dropped.push(k);
  }
  return { env: kept, dropped: dropped.sort() };
}

/** Trivy's log lines at WARN or above, as { level, message, fields }. */
export function trivyLog(stderr) {
  const out = [];
  for (const line of String(stderr || "").split("\n")) {
    const parts = line.split("\t");
    if (parts.length < 3 || !/^(?:WARN|ERROR|FATAL)$/.test(parts[1])) continue;
    out.push({ level: parts[1], message: parts[2].trim(), fields: parts.slice(3).join(" ").trim() });
  }
  return out;
}

function plural(n, one, many) {
  return n === 1 ? one : many;
}

/**
 * The verdict on one Trivy report. Pure, so it is tested on real reports.
 * @param {{ image: string, severity: string, report: object, log: Array<{level, message, fields}> }} input
 * @returns {{ failures: string[], advisories: string[], couldNotRun: string[] }}
 */
export function judgeTrivyReport({ image, severity = DEFAULT_SEVERITY, report, log = [] }) {
  const failures = [];
  const advisories = [];
  const couldNotRun = [];
  const label = `trivy (${image})`;
  if (!report || report.SchemaVersion !== 2) {
    couldNotRun.push(
      `${label}: the report is schema version ${report ? JSON.stringify(report.SchemaVersion) : "missing"}, and this version of wolfproof reads version 2; the image was not checked.`
    );
    return { failures, advisories, couldNotRun };
  }
  const version = report.Trivy?.Version ? `Trivy ${report.Trivy.Version}` : "Trivy";
  const osInfo = report.Metadata?.OS || null;
  const osName = osInfo ? `${osInfo.Family} ${osInfo.Name}` : null;
  const results = report.Results || [];
  const at = SEVERITIES.indexOf(severity);

  const blocking = new Map();
  let unfixed = 0;
  let below = 0;
  for (const result of results) {
    for (const v of result.Vulnerabilities || []) {
      const key = `${v.VulnerabilityID}|${v.PkgName}|${v.InstalledVersion}|${result.Target}`;
      const rank = SEVERITIES.indexOf(v.Severity);
      if (rank >= at && v.FixedVersion) blocking.set(key, v);
      else if (rank >= at) unfixed++;
      else below++;
    }
  }

  if (blocking.size) {
    const sorted = [...blocking.values()].sort(
      (a, b) => SEVERITIES.indexOf(b.Severity) - SEVERITIES.indexOf(a.Severity) || a.VulnerabilityID.localeCompare(b.VulnerabilityID)
    );
    const shown = sorted
      .slice(0, SHOWN)
      .map((v) => `${v.Severity} ${v.VulnerabilityID} in ${v.PkgName} ${v.InstalledVersion}, fixed in ${v.FixedVersion}`);
    const more = sorted.length > SHOWN ? `; and ${sorted.length - SHOWN} more` : "";
    failures.push(
      `${label}: ${blocking.size} ${plural(blocking.size, "vulnerability", "vulnerabilities")} at ${severity} or above ` +
        `${plural(blocking.size, "has", "have")} a fixed version — ${shown.join("; ")}${more}. Upgrade those packages or the base image.`
    );
  }
  if (unfixed + below) {
    const parts = [];
    if (unfixed) parts.push(`${unfixed} at ${severity} or above with no fixed version yet`);
    if (below) parts.push(`${below} below ${severity}`);
    advisories.push(`${label}: ${unfixed + below} more ${plural(unfixed + below, "vulnerability does", "vulnerabilities do")} not block — ${parts.join(", ")}.`);
  }

  // Past its end of service life: the distribution publishes no more advisories, so what was found
  // since is not in the database. The fix is the project's -- a supported base image.
  if (osInfo?.EOSL) {
    advisories.push(
      `${label}: ${osName} is past its end of service life, so vulnerabilities found since are not in Trivy's database and are not reported. Move to a supported base image.`
    );
  }

  // An OS Trivy has no advisories for reads exactly like a clean one. "Not on the EOL list" alone
  // is not that -- Trivy 0.74 says it of Alpine 3.24 and finds its vulnerabilities -- but with no
  // vulnerabilities at all in the OS packages, the two cannot be told apart.
  const osResult = results.find((r) => r.Class === "os-pkgs");
  const unknownVersion = log.some((l) => /^This OS version is not on the EOL list/.test(l.message));
  let osUnchecked = false;
  if (osInfo && !osResult) {
    osUnchecked = true;
    advisories.push(`${label}: Trivy detected ${osName} and did not scan its packages, so the OS packages were not checked.`);
  } else if (osResult && unknownVersion && !(osResult.Vulnerabilities || []).length) {
    osUnchecked = true;
    advisories.push(
      `${label}: Trivy does not recognise ${osName} and found no vulnerabilities in its packages, which can mean it has no advisories for that version rather than that there are none.`
    );
  }

  for (const l of log) {
    if (l.level === "FATAL" || NOTHING_TO_ADD.some((re) => re.test(l.message))) continue;
    advisories.push(`${label}: Trivy reported a problem and carried on: ${l.message}${l.fields ? ` (${l.fields})` : ""}.`);
  }

  // The line that reads as a pass, so not beside one that says the OS packages went unchecked.
  if (!blocking.size && !osUnchecked) {
    if (!results.length && !osInfo) {
      advisories.push(`${label}: ${version} found no OS packages and no language packages in the image, so there was nothing to scan.`);
    } else {
      const targets = results.map((r) => (r.Class === "os-pkgs" && osName ? osName : r.Target)).join(", ");
      advisories.push(`${label}: ${version} scanned ${targets || "the image"}; nothing at ${severity} or above has a fixed version.`);
    }
  }
  return { failures, advisories, couldNotRun };
}

/**
 * Scan one image and judge the report. Trivy is WOLFPROOF_TRIVY when that is set -- the Action sets
 * it to the binary it installed and verified, so a failed install is "not installed" rather than
 * whatever trivy the runner has -- and otherwise the trivy on PATH.
 * @returns {{ ran: boolean, failures: string[], advisories: string[], couldNotRun: string[] }}
 */
export function scanImage(image, { severity = DEFAULT_SEVERITY, env = process.env } = {}) {
  const label = `trivy (${image})`;
  const command = setting(env, "TRIVY") || "trivy";
  // An empty directory to run in: Trivy reads .trivyignore and trivy.yaml from where it runs, and
  // the project's would let the project decide what its own scan reports.
  const dir = mkdtempSync(path.join(os.tmpdir(), "wolfproof-trivy-"));
  const output = path.join(dir, "report.json");
  const ignore = path.join(dir, "empty.trivyignore");
  writeFileSync(ignore, "");
  const { env: runEnv, dropped } = trivyEnv(env);
  try {
    const r = spawnSync(
      command,
      [
        "image", "--scanners", "vuln", "--format", "json", "--output", output,
        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignorefile", ignore,
        "--skip-version-check", "--no-progress", image,
      ],
      { cwd: dir, encoding: "utf8", env: runEnv, timeout: TIMEOUT_MS, killSignal: "SIGKILL", maxBuffer: 16 * 1024 * 1024 }
    );
    const notes = dropped.length ? [`${label}: ${dropped.join(", ")} ${plural(dropped.length, "is", "are")} set and not passed to Trivy, because ${plural(dropped.length, "it", "they")} can change what the scan reports.`] : [];
    if (r.error?.code === "ENOENT") {
      return { ran: false, failures: [], advisories: notes, couldNotRun: [`${label}: ${command === "trivy" ? "trivy is not installed" : `${command} does not exist`}, so the image was not scanned.`] };
    }
    if (r.error) {
      return { ran: false, failures: [], advisories: notes, couldNotRun: [`${label}: trivy did not finish (${r.error.code || r.error.message}), so the image was not checked.`] };
    }
    const log = trivyLog(r.stderr);
    if (r.status !== 0) {
      const fatal = log.find((l) => l.level === "FATAL");
      const why = fatal ? `${fatal.message}${fatal.fields ? `: ${fatal.fields}` : ""}` : String(r.stderr || "").trim().split("\n").pop() || `exit ${r.status}`;
      return { ran: false, failures: [], advisories: notes, couldNotRun: [`${label}: the scan failed, so the image was not checked — ${why.slice(0, 400)}`] };
    }
    let report;
    try {
      report = JSON.parse(readFileSync(output, "utf8"));
    } catch (err) {
      return { ran: false, failures: [], advisories: notes, couldNotRun: [`${label}: the scan finished without a readable report (${err.message}), so the image was not checked.`] };
    }
    const judged = judgeTrivyReport({ image, severity, report, log });
    return { ran: !judged.couldNotRun.length, ...judged, advisories: [...notes, ...judged.advisories] };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
