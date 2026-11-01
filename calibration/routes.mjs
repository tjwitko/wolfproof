#!/usr/bin/env node
// The authentication check against real applications: how many routes it reads in each, and how
// many it reports open, exempt, not read, or blocking.
//
//   node calibration/routes.mjs                  compare against calibration/routes.json
//   node calibration/routes.mjs --update         re-measure and freeze what was measured
//   node calibration/routes.mjs --only=a,b       just those apps
//   node calibration/routes.mjs --checkouts=DIR  use DIR/<app> where it is already at the pinned commit,
//                                                and DIR/<app>.tgz for a package with the pinned integrity
//   node calibration/routes.mjs --offline        fetch nothing: what --checkouts lacks is not measured
//   node calibration/routes.mjs --wolfproof=DIR  measure another copy of this project, such as an
//                                                earlier release, against the same apps
//
// manifest.json pins the apps the sast counts are measured on. The release notes' route figures were
// measured on more than that, and this pins the rest, so the figures can be measured again:
//
//   - "from": "manifest" names an app pinned in manifest.json, at that commit;
//   - "repo" and "commit" pin one that is only here;
//   - "npm", "version" and "integrity" pin a published package, of which only "paths" are kept;
//   - "from": "corpus" names a deliverable in corpus/fixtures.tar.gz.
//
// --wolfproof=DIR reproduces a before-and-after: run it on a `git archive` of the earlier tag, then
// without it, and compare the totals each prints. Only the default compares against the frozen counts
// as a check; with --wolfproof the differences are printed and the exit is 0 unless something could
// not be measured.
//
// SCAN ONLY. Nothing is built, installed or run: each app is cloned with hooks and LFS off, or
// unpacked with tar, read by the authentication check in-process, and deleted.
//
// Exit: 0 every app matches, 1 a count moved, 3 something could not be measured.
import { execFileSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

import { checkout, existing, npmPackage } from "./fetch.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const arg = (name) => (process.argv.find((a) => a.startsWith(`--${name}=`)) || "").slice(name.length + 3);
// --manifest= and --sast-manifest= are for testing the runner against copies.
const MANIFEST = path.resolve(arg("manifest") || path.join(__dirname, "routes.json"));
const SAST_MANIFEST = path.resolve(arg("sast-manifest") || path.join(__dirname, "manifest.json"));
const CORPUS = path.resolve(arg("corpus") || path.join(__dirname, "..", "corpus", "fixtures.tar.gz"));
const WOLFPROOF = arg("wolfproof") ? path.resolve(arg("wolfproof")) : null;
const UPDATE = process.argv.includes("--update");
const CHECKOUTS = arg("checkouts");
const OFFLINE = process.argv.includes("--offline");
const ONLY = arg("only").split(",").filter(Boolean);
const EXIT = { MATCH: 0, DRIFT: 1, INCOMPLETE: 3 };

if (UPDATE && WOLFPROOF) {
  console.error("routes: --update freezes this copy's counts, so it does not take --wolfproof");
  process.exit(2);
}
const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const sast = new Map(JSON.parse(readFileSync(SAST_MANIFEST, "utf8")).apps.map((a) => [a.name, a]));
const wanted = (name) => !ONLY.length || ONLY.includes(name);
for (const name of ONLY) {
  if (!manifest.apps.some((a) => a.name === name)) {
    console.error(`routes: --only names ${name}, which is not in ${path.basename(MANIFEST)}`);
    process.exit(2);
  }
}

const auth = await import(pathToFileURL(path.join(WOLFPROOF || path.join(__dirname, ".."), "agent", "authentication.mjs")).href);

let corpusRoot = null;
function corpusDir(name) {
  if (!corpusRoot) {
    corpusRoot = mkdtempSync(path.join(tmpdir(), "calibration-corpus-"));
    execFileSync("tar", ["-xzf", CORPUS, "-C", corpusRoot]);
  }
  return { dir: path.join(corpusRoot, name), kept: true };
}
process.on("exit", () => corpusRoot && rmSync(corpusRoot, { recursive: true, force: true }));

async function source(app) {
  if (app.from === "corpus") return corpusDir(app.name);
  if (app.npm) return npmPackage(CHECKOUTS, app, { offline: OFFLINE });
  const pin = app.from === "manifest" ? sast.get(app.name) : app;
  if (!pin) return { error: `${app.name} is not in ${path.basename(SAST_MANIFEST)}` };
  const kept = existing(CHECKOUTS, app.name, pin.commit);
  if (kept) return kept;
  if (OFFLINE) return { error: `no checkout of ${pin.commit.slice(0, 12)} in the checkouts, and offline` };
  return checkout(pin.repo, pin.commit);
}

function measure(dir) {
  const a = auth.checkAuthentication(dir);
  const blocking = (auth.authenticationFailures(dir).failures || []).length;
  return {
    routes: a.routes.length,
    open: a.routes.filter((r) => !r.protectedBy).length,
    exempt: (a.exempt || []).length,
    unread: (a.unread || []).length,
    blocking,
  };
}

const KEYS = ["routes", "open", "exempt", "unread", "blocking"];
const show = (c) => KEYS.map((k) => `${c[k]} ${k}`).join(", ");
const total = { projects: 0, routes: 0, open: 0, blockingProjects: 0 };

console.log(`routes: ${manifest.apps.filter((a) => wanted(a.name)).length} of ${manifest.apps.length} apps${WOLFPROOF ? `, measured with ${WOLFPROOF}` : ""}${UPDATE ? " — RE-MEASURING" : `, counts measured ${manifest.measured}`}\n`);
let drifted = 0;
let incomplete = 0;
for (const app of manifest.apps) {
  if (!wanted(app.name)) continue;
  const co = await source(app);
  if (co.error) {
    console.log(`  INCOMPLETE ${app.name} — could not fetch: ${co.error}`);
    incomplete++;
    continue;
  }
  let got;
  try {
    got = measure(co.dir);
  } catch (err) {
    console.log(`  INCOMPLETE ${app.name} — ${err.message}`);
    incomplete++;
    continue;
  } finally {
    if (!co.kept) rmSync(co.dir, { recursive: true, force: true });
  }
  total.projects++;
  total.routes += got.routes;
  total.open += got.open;
  if (got.blocking) total.blockingProjects++;
  if (UPDATE) {
    app.expected = got;
    console.log(`  measured ${app.name}  ${show(got)}`);
    continue;
  }
  const moved = KEYS.filter((k) => app.expected?.[k] !== got[k]);
  if (moved.length) {
    drifted++;
    console.log(`  DRIFT    ${app.name}  ${moved.map((k) => `${k} ${app.expected?.[k]} -> ${got[k]}`).join(", ")}`);
  } else {
    console.log(`  ok       ${app.name}  (${show(got)})`);
  }
}

console.log(`\n${total.projects} apps: ${total.routes} routes, ${total.open} open; ${total.blockingProjects} apps blocked by the authentication check.`);
if (incomplete) {
  console.log(`${incomplete} app(s) could not be measured${UPDATE ? "; routes.json was NOT written" : ". That is not a match: nothing was compared for them"}.`);
  process.exit(EXIT.INCOMPLETE);
}
if (UPDATE) {
  manifest.measured = new Date().toISOString().slice(0, 10);
  writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`wrote ${path.relative(process.cwd(), MANIFEST)}`);
  process.exit(EXIT.MATCH);
}
if (drifted && !WOLFPROOF) {
  console.log(`${drifted} app(s) drifted. A route that moved to open, or one no longer read, may be a regression; one`);
  console.log(`that moved to protected may be a false credit. If the change is deliberate, re-measure with --update`);
  console.log(`and say in the commit which counts moved and why.`);
  process.exit(EXIT.DRIFT);
}
if (drifted) console.log(`${drifted} app(s) differ from the frozen counts, as measured with ${WOLFPROOF}.`);
else console.log(`all ${total.projects} apps match.`);
