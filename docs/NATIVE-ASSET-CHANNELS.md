# Native asset channel hooks

The `feature/taproot-assets-lightning` branch supports Taproot Asset channels
through an auxiliary provider installed before constructing `LightningNode`.
The complete asset wallet, proof, quote and recovery integration is in the
[ts-tap companion branch](https://github.com/coreyphillips/ts-tap/tree/feature/native-asset-lightning).
See its [integration guide](https://github.com/coreyphillips/ts-tap/blob/feature/native-asset-lightning/docs/lightning.md)
for a configured public service and funding/payment examples.

`INodeConfig.auxiliaryChannels` supplies the commitment provider and
funding, HTLC valuation, quote reservation and terminal settlement callbacks.
Nodes advertise overlay support only when this provider is configured. The
deployed optional bit is 2025 and the required channel type bit is 2026.
Asset channels use native v1 funding and MuSig2 commitments.

The provider returns Taproot leaves and opaque recovery data for each signed
commitment. Native channel storage retains these beside Bitcoin signatures,
HTLC state and revocation records. A restored asset channel requires its
provider again; missing providers fail closed. Every native channel reconstruction
must pass the configured provider, including startup, rollback and recovery.

Funding validation hooks can wait for asynchronous proof verification before
sending accept_channel or signing funding_created. Pending checks are bounded,
duplicates are coalesced, conflicting messages abort, and detach invalidates
late completions. The native persistence and replication barriers remain the
only authority that releases funding transactions and signed commitments.

Incoming HTLC valuation separates the physical Bitcoin carrier from the quoted
payment value. Outgoing asset payments bind a channel and expected HTLC ID.
Terminal auxiliary callbacks come from a durable journal and are replayed until
acknowledged. Ordinary route selection and automatic invoice hints exclude
asset channels.

Auxiliary sweep hooks run before Bitcoin signatures are made. They retain
contract resolution data in monitor snapshots so the asset layer can rebuild
proofs after confirmation, a process restart or a reorganization. Local justice
supports the additional asset leaves. The standard external watchtower V1 blob
cannot carry them and is refused for these channels.

Taproot splice and FFOR restrictions also apply to overlay channels. Blinded
asset payment routing and dual-funded asset opening are outside the companion
service's supported API. Ordinary Bitcoin channels retain their existing wire
format, commitment logic and route selection behavior.

When installing this branch from Git, the package's prepare step builds its
TypeScript distribution. Applications should pin a reviewed commit instead of
following a moving branch in their lockfile.
