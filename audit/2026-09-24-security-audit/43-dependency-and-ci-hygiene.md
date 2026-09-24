# Dependency and CI hygiene: qs advisories under bip21 pass the audit gate, the Electrum client library disables TLS verification, workflows run with default token permissions and mutable action tags

Labels: bug

Found during a security audit. Low-severity hygiene items; the TLS point is also referenced from the UTXO-value issue where it becomes a money-loss amplifier.

## 1. `qs` 6.15.3 under `bip21` carries two moderate advisories that the CI gate ignores

`npm audit` reports GHSA-x5fp-wj9c-mxmx (array-limit bypass) and GHSA-4mjr-xmp4-gh2g (DoS via attacker-controlled isBuffer) for `qs@6.15.3`, reached through `bip21@2.0.3` (`qs: ^6.3.0`). `qs` is used to parse BIP 21 URI query strings, i.e. attacker-supplied input from QR codes and pasted links. `fixAvailable: true` (qs >= 6.16.0 is within bip21's range), but `.github/workflows/audit.yml` runs `npm audit --audit-level=high`, so moderate advisories pass silently.

Fix: `npm update qs` (or add `qs` to `overrides`), and consider `--audit-level=moderate` for a wallet.

## 2. `rn-electrum-client` hardcodes `rejectUnauthorized: false`

`node_modules/rn-electrum-client/lib/TlsSocketWrapper.js:72` and `lib/init_socket.js:21` connect with certificate verification disabled and beignet offers no pinning or CA option, so every "TLS" Electrum session, including the default `fulcrum.bitkit.blocktank.to:8900`, accepts any on-path certificate. Electrum servers commonly use self-signed certificates, which is why clients usually pin on first use; beignet does neither. The README makes no verification promise, but users reading "tls" will assume one.

Fix: expose a verification mode (CA verification for hosts with real certificates, trust-on-first-use pinning otherwise) and document the current behaviour until then.

## 3. GitHub Actions hygiene

No workflow declares a `permissions:` block, so jobs run with the repository's default `GITHUB_TOKEN` scopes; actions are pinned to mutable major tags (`actions/checkout@v7`, `actions/setup-node@v7`, `jwalton/gh-docker-logs@v2`) rather than commit SHAs; `tests.yml` runs `sudo apt install wait-for-it` unpinned. A compromised action tag or apt mirror gets whatever the default token allows.

Fix: add `permissions: contents: read` at the workflow level, pin actions by SHA (Dependabot can keep them current), and pin or vendor `wait-for-it`.
