# Security policy

Beignet holds keys and moves funds, so a bug in it can cost its users money. Report anything that could lose, lock or misdirect funds, or expose keys, privately and not in a public issue. If you are not sure whether a bug can be exploited, report it privately anyway.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: on the repository's Security tab choose **Report a vulnerability**, or go straight to <https://github.com/coreyphillips/beignet/security/advisories/new>. Only you and the maintainers can see the report.

Until a fix is published, do not open an issue, pull request or discussion about it, and do not post it in the Telegram group.

A useful report gives:

- the beignet version (`npm ls beignet`) or commit, and the entry point: `beignet`, `beignet/node`, `beignet/lightning`, the daemon or the CLI;
- the network it was seen on;
- what an attacker needs (a peer connection, a daemon API token, a malicious Electrum server, local file access) and what they get;
- steps or a test that reproduce it.

Test against your own nodes and wallets only, and do not move funds that are not yours.

## What happens next

- You get an acknowledgement within 3 days.
- You get an assessment within 14 days: whether the report is accepted, how severe it is, and the plan to fix it.
- Progress is posted in the private advisory until the fix ships.
- The advisory is published once a fixed version is on npm, crediting you unless you ask not to be. A CVE is requested through the advisory where one applies.

Please allow 90 days from the report for a fix before disclosing it yourself. If a fix needs longer, you will be told why.

## Supported versions

Beignet is pre-1.0. Fixes ship in the next release from `master`, and older versions are not patched, so a fix reaches you by upgrading to the newest version on npm.

## Scope

In scope is any code in this repository, including the library, the daemon and the CLI, that can:

- lose, lock or misdirect funds, on chain or in a channel;
- expose a mnemonic, private key, channel secret or backup;
- let a peer, an Electrum server or an HTTP client do something its credentials should not allow;
- be made by a remote party to crash or stall a node in a way that puts funds at risk, such as missing a breach or HTLC deadline.

Out of scope are bugs in dependencies that beignet does not make reachable (report those upstream), and attacks that need root or the node's own OS user.
