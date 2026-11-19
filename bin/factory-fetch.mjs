#!/usr/bin/env node
// What the Action fetches before the gate runs in factory mode (action.yml):
//
//   node bin/factory-fetch.mjs <project-dir> <base>
//
// actions/checkout fetches depth 1 by default. For a pull request that is the merge commit and
// neither parent's history; for a push, the pushed head alone. Factory mode needs two things beside
// it:
//
//   1. The base commit, to compare the two trees. Fetched by itself at depth 1; a base written from
//      the head (HEAD~1, the fallback for a push that creates a branch) is fetched by deepening one
//      level.
//   2. Every commit between the base and the head, because the gate scans what each of them added
//      for credentials (lib/factory-commits.mjs): one that a commit added and a later commit removed
//      is in neither tree. The history is deepened from where the clone was cut, 50 commits, then
//      250, then 1250, until no commit on either side of the base and the head is one whose parents
//      are missing. Either side, since the base's own history down to the fork point is what tells
//      git where the change starts. Measured on a pull request of 4 commits whose base had moved 5
//      past the fork point, and on a push of 4: both were complete after deepening by 6.
//
// It decides nothing. The gate asks whether the commits are all there with the same function
// (commitRange) and reports the scan as could not run when they are not, so a fetch that fails, or
// a change longer than 1550 commits, is exit 3 and never a pass. Always exits 0.
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { realpathSync } from "fs";

import { commitRange } from "../lib/factory-commits.mjs";

export const DEEPEN = [50, 250, 1250];

/** @returns {{ base: string | null, fetched: string[], commits: number | null, complete: boolean, why?: string }} */
export function fetchForFactory(projectDir, base, { deepen = DEEPEN } = {}) {
  const git = (...args) => spawnSync("git", ["-C", projectDir, ...args], { encoding: "utf8" });
  const resolve = (ref) => {
    const r = git("rev-parse", "--verify", "--quiet", `${ref}^{commit}`);
    return r.status === 0 ? r.stdout.trim() : null;
  };
  const fetched = [];
  const fetch = (...args) => {
    fetched.push(args.join(" "));
    return git("fetch", "--no-tags", "--quiet", ...args).status === 0;
  };
  if (!resolve(base)) {
    if (/[~^]/.test(base)) fetch("--deepen=1", "origin");
    else fetch("--depth=1", "origin", base);
  }
  const sha = resolve(base);
  const head = resolve("HEAD");
  if (!sha || !head) return { base: sha, fetched, commits: null, complete: false, why: sha ? "HEAD names no commit" : `the base ${base} is not in the checkout` };
  let range = commitRange(projectDir, sha);
  for (const n of deepen) {
    if (!range.incomplete) break;
    if (!fetch(`--deepen=${n}`, "origin", head, sha)) break;
    range = commitRange(projectDir, sha);
  }
  return { base: sha, fetched, commits: range.commits ? range.commits.length : null, complete: !range.error, ...(range.error ? { why: range.error } : {}) };
}

const isEntry = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isEntry) {
  const [projectDir, base] = process.argv.slice(2);
  if (!projectDir || !base) {
    console.log("factory: usage: factory-fetch.mjs <project-dir> <base>");
  } else {
    const r = fetchForFactory(projectDir, base);
    console.log(
      r.complete
        ? `factory: ${r.commits} commit(s) between the base and the head are in the checkout${r.fetched.length ? ` (fetched: ${r.fetched.map((f) => `git fetch ${f.replace(/ [0-9a-f]{40,}/g, " <sha>")}`).join("; ")})` : ""}`
        : `factory: the commits between the base and the head are not all in the checkout, and the gate will say so — ${r.why}`
    );
  }
}
