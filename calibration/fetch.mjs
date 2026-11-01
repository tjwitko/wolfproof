// Getting a calibration app's code: exactly the pinned commit or package, and nothing else.
// Shared by run.mjs (the sast counts) and routes.mjs (the authentication check's routes).
import { execFileSync } from "child_process";
import { createHash } from "crypto";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";

/**
 * An existing checkout at exactly `commit`, or null. Every file in it counts towards what is
 * measured, so a checkout with anything changed, added or ignored-but-present is not the commit.
 */
export function existing(checkouts, name, commit) {
  if (!checkouts) return null;
  const dir = path.resolve(checkouts, name);
  const git = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  try {
    if (git("rev-parse", "HEAD") !== commit) return null;
    if (git("status", "--porcelain", "--untracked-files=all", "--ignored") !== "") return null;
    return { dir, kept: true };
  } catch {
    return null;
  }
}

/** Clone exactly one commit, shallow, into a fresh directory. Runs nothing from the repository. */
export function checkout(repo, commit) {
  const dir = mkdtempSync(path.join(tmpdir(), "calibration-"));
  const git = (...args) =>
    execFileSync("git", ["-C", dir, "-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false", ...args], {
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, GIT_LFS_SKIP_SMUDGE: "1", GIT_TERMINAL_PROMPT: "0" },
      timeout: 600_000,
    });
  try {
    git("init", "-q");
    git("fetch", "-q", "--depth", "1", "--no-tags", repo, commit);
    git("checkout", "-q", "FETCH_HEAD");
    return { dir };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    return { error: (err.stderr ? String(err.stderr) : err.message).trim().split("\n").pop() };
  }
}

/** The npm registry's tarball for a package version. */
export function tarballUrl(pkg, version) {
  return `https://registry.npmjs.org/${pkg}/-/${pkg.split("/").pop()}-${version}.tgz`;
}

/**
 * A published npm package, held to its sha512 integrity, with only `paths` ({ dest: path in the
 * tarball }) copied out. The tarball is read from `<checkouts>/<name>.tgz` when that file has the
 * pinned integrity, and downloaded otherwise, unless `offline`. It is unpacked with tar and nothing
 * in it is run.
 */
export async function npmPackage(checkouts, app, { offline = false } = {}) {
  const local = checkouts ? path.resolve(checkouts, `${app.name}.tgz`) : null;
  let bytes = local && existsSync(local) ? readFileSync(local) : null;
  if (!bytes || sri(bytes) !== app.integrity) {
    if (offline) return { error: `no ${app.name}.tgz with the pinned integrity in the checkouts, and offline` };
    try {
      const res = await fetch(tarballUrl(app.npm, app.version));
      if (!res.ok) return { error: `${tarballUrl(app.npm, app.version)} answered ${res.status}` };
      bytes = Buffer.from(await res.arrayBuffer());
    } catch (err) {
      return { error: err.message };
    }
  }
  if (sri(bytes) !== app.integrity) return { error: `${app.npm}@${app.version} has integrity ${sri(bytes)}, not the pinned one` };
  const dir = mkdtempSync(path.join(tmpdir(), "calibration-"));
  const unpacked = mkdtempSync(path.join(tmpdir(), "calibration-tgz-"));
  try {
    writeFileSync(path.join(unpacked, "package.tgz"), bytes);
    execFileSync("tar", ["-xzf", path.join(unpacked, "package.tgz"), "-C", unpacked]);
    for (const [dest, from] of Object.entries(app.paths)) {
      const src = path.join(unpacked, from);
      if (!existsSync(src)) throw new Error(`${from} is not in ${app.npm}@${app.version}`);
      cpSync(src, path.join(dir, dest), { recursive: true });
    }
    return { dir };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    return { error: err.message };
  } finally {
    rmSync(unpacked, { recursive: true, force: true });
  }
}

function sri(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}
