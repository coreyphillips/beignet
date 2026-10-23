# Contributing

Beignet moves real funds, so changes are small, tested, and reviewable one at a time. Security vulnerabilities are not reported here: see [SECURITY.md](SECURITY.md).

## Setup

Use Node.js 24 (24.22.1+), the version CI runs, and install with `npm ci`. The [Tests](README.md#tests) section of the README lists every suite. `npm run test:local` runs the Lightning and CLI suites, which need no network or Docker. The on-chain suites in `tests/*.test.ts` connect to live Electrum servers.

## Checks

CI runs each of these on every pull request, and all must pass:

- `npm run lint:check`
- `npm run tsc:check`, then `npm run build` and `npm run tsc:check:tests`
- `npm run test:api`. A PR that changes the exported API commits the snapshot that `npm run api:snapshot` regenerates, and the snapshot diff is reviewed with the code.
- `npm run docs:check` and `npm run docs:paths`. A new markdown file also needs a link in [docs/README.md](docs/README.md).
- `npm audit --audit-level=moderate`
- the test suites in [.github/workflows/tests.yml](.github/workflows/tests.yml)

A bug fix comes with a test that fails without it.

## Pull requests

- **One pull request per step.** An issue with a checklist of steps (1.9a, 4B.1 and so on) is done one step per PR. The title names the step, as in "Step 4B.1 of #1705: ...", and the other steps stay open.
- **The title is one full sentence about behaviour.** It says what the code does now that it did not before, for example "`ChannelManager` now requires a persistence implementation." PRs are squash-merged, so this sentence is what `git log` on `master` shows.
- **The body says what was wrong, what the change does about it, and how to check it,** with the commands you ran and what they printed. Write `Closes #N` only in the PR that finishes the issue.
- **No attribution lines.** Commits and PR bodies carry no `Co-Authored-By` trailers and no "Generated with" footers.
- **Fund-relevant PRs land alone.** A change to signing, key derivation, coin selection, fee or sweep logic, channel state, HTLC handling, persistence or recovery contains nothing else, and merges only after the full test matrix, interop included, has passed on its final commit. Then if it goes wrong it can be found and reverted by itself.
- **A refactor changes no behaviour, and says so.** A move-only PR reads as moves under `git diff --color-moved`.
