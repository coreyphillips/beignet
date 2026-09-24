# beignet init writes the mnemonic and apiToken to ~/.beignet/config.json with default file permissions, so every local account on the host can read the seed

Labels: bug

Found during a security audit of the CLI and configuration handling.

## Summary

`saveConfig` creates `~/.beignet` and writes `config.json` with no `mode` and no `chmod`. Under the default umask of 022 the directory is 0755 and the file is 0644. `handleInit` puts the freshly generated mnemonic into that file, and `resolveConfig` reads `apiToken` from the same file when the operator configures it there (which `src/cli/README.md` documents as the normal way).

On any multi-user host whose home directories are traversable (the default on Debian, and on Ubuntu before 21.04, and on most container images that run as root with a shared filesystem), every other local account can read the seed. The seed derives the on-chain keys, the Lightning node key, every channel key, and the storage encryption key, so reading it is a total loss of every balance the node holds. The token additionally gives full admin API access to the running daemon.

## Where

- `src/cli/config.ts:52-55`:
  ```ts
  export function saveConfig(config: BeignetConfig): void {
      fs.mkdirSync(beignetDir(), { recursive: true });
      fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n');
  }
  ```
- `src/cli/cli.ts:370-396` (`handleInit`): `newConfig = { ...config, mnemonic, network }` then `saveConfig(newConfig)`.
- `src/cli/config.ts:695-696` (`writePidFile`): same pattern, harmless content.
- `src/cli/beignet-node.ts:1986`: the data directory holding the SQLite database is also created without a mode. Values in the database are AES-GCM encrypted under a seed-derived key, but the lookup columns (payment hashes, channel ids, peer pubkeys, gossip, the action log) are plaintext per `sqlite-storage.ts:179-182`, so the database file is a privacy leak on the same hosts even though it does not leak funds.
- `grep -rn "mode: 0o\|chmod" src/cli` finds nothing.

## Reproduction

With `HOME` pointed at a scratch directory and umask 022, run `beignet init` and stat the results: `~/.beignet` is `drwxr-xr-x`, `config.json` is `-rw-r--r--` and contains `"mnemonic": "..."` (and `"apiToken"` once configured). This was verified with a small script that calls `saveConfig` directly and reads the modes back with `fs.statSync`.

## Suggested fix

- `fs.mkdirSync(dir, { recursive: true, mode: 0o700 })` for `~/.beignet` and for the data directory.
- Write secrets with `{ mode: 0o600 }`. Note that `writeFileSync` on an existing file keeps the file's old mode, so write to a temporary file, `chmod 0o600`, then `rename` over the target (the same shape `beignet-node.ts:711` already uses for its atomic writes).
- On load, if `config.json` is group- or world-readable, either `chmod` it or print a warning naming the file, so existing installs get fixed or at least told.
- Consider the same 0600 treatment for the SQLite database, its WAL and backups, since they are a full history of the node's activity.
