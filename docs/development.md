# Development

```bash
git clone https://github.com/tjwitko/wolfproof
cd wolfproof
npm install
npm test                # unit tests
npm run corpus          # regression corpus — thirteen frozen projects
npm run corpus:factory  # the same thirteen, in factory mode, against their own frozen verdicts
npm run calibration     # the sast rules on 22 real apps, cloned at pinned commits — about 75 minutes
node scripts/refresh-eol-data.mjs   # end-of-life dates for the dockerfile check, before a release
```

## The regression corpus

The corpus is the important one. **Every control defect in this project's history was found by
running real work through the controls, never by a unit test.** `npm run corpus` re-measures
thirteen frozen projects and fails on drift in either direction, because a control that stops
firing is as much a regression as one that starts over-firing.

Eleven are real deliverables, frozen with the verdict each one scored. The other two exist to cover
shapes the graded set does not have — a plain Node library with no infrastructure, and a Python
service — because a corpus in which every fixture was a Terraform-bearing webhook receiver could
not see a check that fires on projects which never asked for what it checks. Adding them found a
live false positive in a blocking validator the same afternoon.

It also records the toolchain that measured it and reports any difference, since a finding count
compared against a different scanner version looks exactly like a control that changed behaviour.

### In factory mode

`npm run corpus:factory` runs the same thirteen in [factory mode](factory-mode.md), each judged as a
change written from nothing — the base is an empty commit before the deliverable, with no allowlist
and no policy — against verdicts frozen separately from the default ones. Measured on 2026-10-20,
factory mode blocks more in eight of them: an unverifiable secret rotation in seven, an undetermined
retention period in one, and a `# noqa` in a test file. None moves from clean to blocked, and none
becomes incomplete.

## The calibration corpus

The calibration corpus does the same for the `sast` rules on other people's code. Its manifest,
[`calibration/manifest.json`](../calibration/manifest.json), names 22 applications by repository and
full commit SHA, with the count each rule gave each one, blocking and advisory, measured with the
pinned semgrep.

`npm run calibration` clones each at that commit, runs the `sast` validator on it — only that:
nothing is built, installed or run — compares, and deletes the clone. A rule that stops finding
WebGoat's SQL injection has broken; one that starts blocking Bitwarden is a false positive on code
people ship. No application's code is copied into this repository. It runs in its own workflow when
the rules or the validator change, and on demand; it is not a required check.

| language | known findings | known clean |
| --- | --- | --- |
| Java | WebGoat | Spring PetClinic, Spring RealWorld |
| Ruby | RailsGoat | rubygems.org, Mastodon |
| JavaScript/TypeScript | Juice Shop | Outline |
| Python | PyGoat | NetBox |
| C# | dvcsharp-api, Jellyfin | eShop, Bitwarden server |
| Go | **none** | Gitea |
| Rust | **none** | Lemmy, Meilisearch |
| C | **none** — Damn Vulnerable C Program's bugs are memory safety, and it correctly scores 0 | curl, git, Redis, nginx |
| C++ | **none** | **none** |
