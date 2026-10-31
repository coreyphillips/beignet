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
Asset channels use MuSig2 commitments. The native interactive extension also
supports dual-funded opening and splicing with retained funding epochs.

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

Before selecting wallet fees for a terminal asset sweep, the node checks the
authenticated source outpoints for confirmed competing spends. This avoids
funding a new claim after a tower has already recovered it. Unconfirmed spends
never suppress fee selection or justice competition. The monitor remains
responsible for confirmation, reorganization and retry handling.

New native asset channels negotiate fixed-output HTLC signatures with channel
bit 450 and optional feature 451. Both signatures use `ALL|ANYONECANPAY`, which
allows fee inputs but commits every output. A bounded durable fee provider is
required before opening. An explicit peer compatibility policy permits the
upstream legacy signature mode; restored channels preserve their original mode.

Optional revoked-child custody uses channel bit 452 and optional feature 453.
It requires mode 450, `allowRevokedChildCustody: true`, and the provider's
`prepareRevokedChild` callback on both peers. This is explicit Bitcoin and asset
custody for children of an exact revoked state. A delegated tower can redirect
those assets. It receives no reusable channel secret and no authority over
Bitcoin-only HTLC children or another commitment. First-level signed remedy
packages remain available without this custody permission.

For each completed commitment transaction, an independent revocation base
secret is derived from the local secret seed and that exact transaction hash.
The asset-bearing child output uses the ordinary revocation combination of
this independent basepoint and the owner's per-commitment point. Only after an
authenticated revocation reveal does a backup include the combined scalar.
Even a peer colluding with its tower can recover only this independent state's
base secret. Funding changes and different allocation or FFoR variants produce
different source hashes and independent authority.

`commitment_signed` custom record 65553 carries version 1, the 32-byte source
transaction ID in display order, and the 33-byte independent basepoint. The
receiver checks the source against the exact signed commitment and persists
this association with its child leaves. Missing records, changed points and
new-channel downgrades are refused. Existing channel types are immutable.

`buildAuxiliaryJusticePackage` includes `childCustody` descriptors only for the
negotiated mode. Each descriptor binds the HTLC branch, fixed child output,
scoped scalar and provider capsule. `matchAuxiliaryJusticeChild` verifies the fixed-output peer signature and the
owner signature against authenticated additional Bitcoin prevouts, including
reordered fee inputs. An owner may change its own signature hash mode; complete
prevout values authenticate non-ANYONECANPAY owner signatures. `buildAuxiliaryChildRemedy` binds the observed child to
its capsule and makes a fixed-output, fee-sponsor-ready recovery transaction.
The companion tower protocol requires a separately acknowledged custody
capability and explicit client/server permission before accepting these backups.

The provider pre-signs the original commitment-to-child asset transition while
creating the capsule. The child-to-wallet asset transition must be signed after
the observed child transaction is known, because virtual asset signatures bind
its Bitcoin outpoint. The narrowly scoped scalar supplies this authority; a
pre-signed destination covenant cannot cover arbitrary child transaction IDs.

Ordinary Bitcoin channels retain their existing wire format, commitment logic
and route selection behavior. The companion guide documents the supported
blinded routing, FFoR and interactive funding APIs.

When installing this branch from Git, the package's prepare step builds its
TypeScript distribution. Applications should pin a reviewed commit instead of
following a moving branch in their lockfile.
