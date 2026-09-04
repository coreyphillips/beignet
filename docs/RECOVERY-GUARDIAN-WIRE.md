# Beignet Recovery Guardian Wire Specification

Version 1 (protocol_version = 1). Companion to docs/RECOVERY-PROTOCOL.md
sections 5.5 to 5.7; this document fixes the exact bytes. The semantic
invariants (per-node linearization, durability before acknowledgment,
cumulative receipts, CAS takeover, backfill) are normative THERE; nothing in
this document relaxes them. Where the two disagree, RECOVERY-PROTOCOL.md
wins and this document has a bug.

Decision context: section 12.1 of RECOVERY-PROTOCOL.md records the transport
and architecture decisions this wire format implements. Revision 4 review
refinements incorporated here: a registration operation under a dedicated
recovery root (2.6, 4.1), the writer lease separated from the log head
(4.2), a normative AEAD nonce construction (3.2), an exact SYNC_EPOCH
validation algorithm (5.7), guardian-set replacement declared a literal v1
non-feature (5.9), and uncertain-store rollback-and-replay repair (5.10).

Style: no em-dashes anywhere, per the repo rule.

---

## 1. Roles and objects

A guardian is a minimal blob store with one nontrivial duty: signed,
monotonic, cumulative receipts (spec 5.5). It never decrypts record
ciphertext. Verbs:

```text
REGISTER_NODE   create a namespace under the recovery root's authority
PUT_STATE       append one record; returns a receipt
GET_HEAD        current guardian state + certificates + receipt
GET_STATE       fetch stored records, paginated
ACQUIRE_EPOCH   CAS writer takeover; returns a takeover certificate
SYNC_RECORD     relay an already-signed record to a lagging guardian
SYNC_EPOCH      present takeover certificates to a guardian that missed one
INFO            capability discovery (GET; not a signed verb)
```

Acceptance is record-level, never connection-level: a record is valid
because its writer signature, epoch binding, and chain position verify.
Transport authentication exists for anti-DoS and privacy (section 9); it is
mandatory for non-local deployments but never a substitute for record
verification.

### 1.1 The recovery root and recovery_id

The guardian namespace is NOT the public Lightning node id. Each node
derives a dedicated recovery root from its identity secret:

```text
okm                  = HKDF-SHA256(ikm = nodeSecret, salt = empty,
                                   info = 'beignet-recovery-root-v1', L = 32)
recovery_root_secret = (int_be(okm) mod (n - 1)) + 1        n = secp256k1 order
recovery_id          = xonly(pubkey(recovery_root_secret))  32 bytes
```

The scalar reduction is exact: interpret the 32 output bytes as a
big-endian integer, reduce modulo n - 1, add 1. The result is always a
valid nonzero scalar, deterministically, with no retry loop and no
implementation-defined behavior on the negligible out-of-range case. The
info string is verified non-colliding with 3.6, 5.3 and 5.4. The
recovery root authorizes exactly two things: initial registration and epoch
acquisition (takeover). It never signs records and never acts as a writer
key. Consequences, both load-bearing:

- Authorization: only a holder of the seed can claim or take over the
  namespace. A fresh random writer key alone proves possession of itself,
  not authority over the namespace; the root signature supplies that.
- Privacy: knowing a node's public Lightning id does not let anyone query
  its guardian history. recovery_id is unlinkable to the Lightning node
  without the seed.

### 1.2 Writer keys

Writer keys are FRESH RANDOM secp256k1 keypairs generated at each
registration or epoch acquisition, 32-byte x-only in transcripts and on the
wire. Never the node identity key, never the recovery root, never derived
from the seed: a superseded device's writer key must die with it, and the
seed alone must not be able to forge records for old epochs.

### 1.3 Guardian identity

`guardianId` is the guardian's long-lived signing public key, 32-byte
x-only. Receipt-key rotation is out of scope for v1 (spec open question
11.6 stays open); a rotated guardian key is a new guardianId and therefore
a new guardian set.

## 2. Transports

Two first-class, normative transports (spec 12.1). The signed objects in
this document never embed URLs or transport details, so the same bytes ride
either transport, a loopback connection, or a future BOLT 8 adapter.

### 2.1 onion-http

HTTP/1.1 over a Tor v3 onion service. TLS is NOT required: the onion
service provides end-to-end encryption and authenticates the service
through the address itself. Guardians SHOULD bind their HTTP listener to
127.0.0.1 and publish it via HiddenServicePort. Private guardians MAY
additionally require Tor v3 client authorization.

### 2.2 https

HTTP/1.1 or HTTP/2 over TLS 1.2 or newer. Certificate validation is
MANDATORY; plaintext HTTP on clearnet is forbidden. A Tor-only wallet MAY
reach an https-only guardian through an exit relay (the payload stays
TLS-protected; the destination is visible to the exit), but wallets with
Tor enabled MUST prefer an onion endpoint when the guardian advertises one.

### 2.3 local-http

Plain HTTP restricted to loopback (127.0.0.1 or ::1), a Unix-domain
socket, or an explicitly isolated container network (the Umbrel
deployment, where the orchestrator guarantees isolation). A general LAN
address does NOT qualify; anything beyond loopback or an isolated
container network MUST use one of the authenticated transports above.

### 2.4 Endpoint descriptors and recoverable credentials

Guardians are addressed by descriptor (the capsule's GuardianDescriptor,
spec 5.4). Selection rule: Tor enabled means the first onion-http
endpoint; otherwise the first https endpoint; local-http only when
explicitly configured. A descriptor with no usable transport is an error
surfaced to the operator, never a silent skip.

Because non-local transports REQUIRE authentication (section 9), the
credential must survive catastrophic restoration or the records behind it
are unreachable exactly when they matter. The descriptor therefore
carries an optional auth member, and a wallet MUST include it in the
capsule for every guardian whose transport needs one:

```ts
auth?:
  | { type: 'bearer';   token: string }
  | { type: 'macaroon'; macaroon: string }         // base64
  | { type: 'tor-v3-client-auth'; privateKey: string }  // base32/64 x25519
```

This is safe precisely because the whole capsule is encrypted under the
seed-derived capsule key (spec 5.4): storage peers never see credentials,
and a seed restore recovers them together with the endpoints. The field
is optional and additive, so Phase 3 capsules without it stay valid. A
derived-credential scheme (per-guardian secrets from the recovery root,
registered as commitments at provisioning) is deliberately deferred: it
needs its own bootstrap and challenge protocol, and encrypted capsule
credentials already close the restore gap in v1.

### 2.5 HTTP mapping

Every verb is `POST /beignet-guardian/v1/<verb-lowercase>` with
`Content-Type: application/x-protobuf` and a protobuf body (section 6).
Discovery is `GET /beignet-guardian/v1/info`. HTTP status is 200 for every
well-formed protocol exchange, INCLUDING protocol-level rejections; the
protocol result lives in the response body's `status` field (section 7).
Non-200 statuses mean the HTTP layer itself failed (404 wrong path, 401
missing or invalid transport credential, 413 body over the advertised
limit, 429 transport-level rate limit with Retry-After, 5xx guardian
down).

### 2.6 Genesis

A guardian serves a recovery_id only after REGISTER_NODE (5.1). Every
other verb against an unregistered recovery_id is `ERR_UNKNOWN_NODE`.
There is no implicit creation: an unknown namespace is never claimable by
whoever asks first with a self-chosen key, because registration demands
the recovery root signature.

### 2.7 bolt8

A guardian hosted IN a beignet node, reached over a dedicated BOLT 8
session to the node's ordinary peer address (issue #699; the "later
optional adapter" spec 12.1 item 1 reserved). Descriptor transport type
`bolt8`, URL `bolt8://<66-hex compressed node id>@<host>:<port>`, guardian
entry `<64-hex guardian id>@bolt8://<node id>@host:port`. The node id is
the key BOLT 8 authenticates the server by; it is NOT a credential and the
`auth` member of the descriptor still carries one when the host requires
it. Nothing signed changes: the same section 4 transcripts and section 6
protobuf bodies ride this transport unchanged.

Session rules:

- The writer opens the session under a FRESH random static key, never its
  node identity key. The guardian sees a stranger, which preserves 1.1
  (recovery_id stays unlinkable to the Lightning node id) and keeps
  guardian traffic structurally off any channel connection. Sessions are
  long-lived; several verbs may be in flight at once.
- Transport security: BOLT 8 supplies encryption and server authentication
  on every network, so a bolt8 endpoint needs no approval on a LAN or
  clearnet (the property local-http lacks). An onion host needs a Tor
  proxy. Endpoint selection ranks bolt8 after onion-http and https and
  before local-http.
- Transport authentication (section 9): the request carries the
  Authorization value verbatim in its `auth` field; a host configured with
  a bearer token compares it in constant time. Running open is acceptable
  for this transport because confidentiality does not depend on the
  credential; it is an allow-list and anti-DoS.

Framing. Every verb rides the beignet custom message (one odd wire type,
44069; `[u16 version][u16 subtype][payload]`) on subtypes 32
GUARDIAN_REQUEST and 33 GUARDIAN_RESPONSE. BOLT 8 caps a message at 65535
bytes, so a request or response is split into ordered chunks that share a
request id. Each chunk payload, big-endian, fixed width:

```text
requestId(4) || verb(1) || totalLength(4) || chunkIndex(2) || chunkCount(2)
then, on chunk 0 only:
  request:  authLength(2) || auth        (at most 4096 bytes)
  response: transportStatus(2)
then this chunk's body bytes
```

Verb codes: 0 INFO, 1 REGISTER_NODE, 2 PUT_STATE, 3 GET_HEAD, 4 GET_STATE,
5 ACQUIRE_EPOCH, 6 SYNC_RECORD, 7 SYNC_EPOCH. The body across chunks is the
exact protobuf bytes of 2.5. Chunks of one request id arrive in order and
contiguous per id (the session is one ordered stream); chunks of DIFFERENT
ids may interleave. A receiver drops the session on any framing violation
(a chunk out of order, a header that changes mid-message, more partial
messages than it allows), and answers a declared length over its cap with
transportStatus 413 once while swallowing that id's remaining chunks, so
the stream stays usable.

A host serves a set only once REGISTER_NODE has run for it (5.1). Before
that, GET_HEAD and GET_STATE for the set answer `ERR_UNKNOWN_NODE`, which
is the truthful "no namespace here" a writer's ownership check reads as
"fresh, register"; every other verb but REGISTER_NODE answers
`ERR_UNKNOWN_SET`. INFO advertises `accepts_registrations` so a writer
binding to the host accepts the set being absent from its list.

`transportStatus` is the 2.5 HTTP-layer status, one to one: 200 for every
well-formed protocol exchange INCLUDING protocol-level rejections (the
result lives in the body's `status` field), 401 refused credential, 404
unknown verb, 413 body over the advertised limit, 500 guardian failure. A
host SHOULD advertise a `max_ciphertext_bytes` well under the 16 MiB
protocol cap (4 MiB matches the guardian-mode snapshot cadence).

## 3. Cryptography

### 3.1 Primitives

- Hash: SHA-256 everywhere. TaggedHash is BIP340's construction:
  `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
- Signatures: BIP340 Schnorr over secp256k1, 64 bytes, over a tagged hash
  of a canonical transcript (section 4). Protobuf bytes are NEVER signed:
  protobuf serialization is not canonical (spec 12.1).
- All public keys in transcripts and on the wire are 32-byte x-only
  (implicitly even-Y, per BIP340). No 33-byte compressed forms appear
  anywhere in this protocol.

### 3.2 Record ciphertext AEAD and nonce construction

Record ciphertext is the journal frame as stored (spec 5.3): AES-256-GCM,
layout `iv(12) || authTag(16) || ciphertext`, per-epoch frame key, AAD
binding (nodeId, writerEpoch, sequence, previousFrameHash). The guardian
treats it as opaque bytes. Uniform AES-256-GCM settles spec open question
11.2.

The 96-bit IV is DETERMINISTIC from revision 4 on:

```text
iv = first_12_bytes(
    TaggedHash('beignet/recovery/aes-gcm-iv/v1',
        recovery_id(32)
        || writerEpoch(8)
        || sequence(8)
        || frameHash(32)))
```

The derivation input is recovery_id, NEVER the Lightning node id: epoch,
sequence, frameHash and the IV itself are all visible in a stored record,
so an IV derived from the node id would let anyone test a candidate
Lightning identity against a record and break the unlinkability property
of 1.1. recovery_id is already known to the guardian as the namespace, so
deriving from it reveals nothing new to anyone. (A keyed derivation from
the frame key would hide even cross-record structure, but the unkeyed
recovery_id form already delivers the stated privacy property and keeps
the IV computable without touching key material.) The journal receives
recovery_id at construction when the Phase 4 implementation lands; its
frame keys and AAD (5.3) are unaffected, and neither is testable without
the secret master key.

Uniqueness argument: the frame key is per (node, writerEpoch), so a
(key, IV) collision requires equal epoch, equal sequence AND equal
frameHash, which means the identical plaintext, and re-encrypting the
identical plaintext under the same key and IV yields the identical
ciphertext: harmless. Distinct plaintext at the same position produces a
distinct frameHash and therefore a distinct IV. This construction is
robust where random IVs are not: a VM snapshot rollback that replays RNG
state cannot cause a catastrophic (key, IV) reuse across different
plaintexts.

Frames produced before revision 4 used uniformly random IVs from the OS
CSPRNG; they remain valid and decryptable forever, because the IV travels
with the ciphertext and decryption never re-derives it. Test vectors for
the tagged hashes, transcripts, and IV derivation ship with the Phase 4
reference implementation, as section 9 of the main spec requires.

## 4. Canonical transcripts and domain separation

All multi-byte integers are unsigned big-endian, fixed width. Every signed
object begins with:

```text
PREFIX = protocol_version(2) || guardian_set_id(32)
```

`guardian_set_id` commits to the set and its policy:

```text
guardian_set_id = TaggedHash('beignet/recovery/guardian-set/v1',
    profile_id(2)
    || required(2)
    || total(2)
    || sorted_ascending(guardianId_1(32) .. guardianId_n(32)))
```

Profile `crash-v1` is `profile_id = 1`, `required = 2`, `total = 3`. It is
the ONLY profile in v1 (spec 12.1): implementations MUST reject any other
(profile_id, required, total) combination. The encoding carries the fields
so a future Byzantine profile (for example 3-of-4) slots in without a wire
break.

### 4.1 The state pair: writer lease and log head

The guardian's per-node state is two separable pieces. Conflating them
breaks the takeover transition, so every transcript that used to carry a
single "head" carries this pair:

```text
LEASE   = epoch(8) || writerPublicKey(32)

ORIGIN  = firstSequence(8) || previousHash(32)

LOGHEAD = sequence(8) || frameHash(32) || ciphertextHash(32) || recordEpoch(8)

STATE   = recovery_id(32) || LEASE || ORIGIN || LOGHEAD
```

- LEASE is who may write now.
- ORIGIN is the IMMUTABLE, root-committed chain origin, fixed at
  registration and never changing for the life of the namespace. For a
  fresh node it is `firstSequence = 1, previousHash = 32 zero bytes`.
  For an EXISTING node enabling guardians mid-journal, it is the
  retained base snapshot's real position: `firstSequence = K,
  previousHash = the journal hash preceding K`. This is what lets the
  node-wide journal numbering (spec 5.3) carry over without renumbering,
  while making the origin independently authenticated: it is inside the
  root-signed REGISTER transcript, not inferred from whichever record
  happens to survive in a database. A guardian whose earliest stored
  record does not sit on a verified chain from ORIGIN knows it has lost
  history (5.10); a bare surviving record can never masquerade as an
  origin.
- LOGHEAD is the tip of the record log: the last stored record's sequence,
  hashes, and the epoch THAT RECORD was written under. After a takeover,
  `recordEpoch < lease.epoch` until the new writer's first append.
- Genesis LOGHEAD is `sequence = 0`, both hashes all zeros,
  `recordEpoch = 0`, meaning "no records stored yet"; the ORIGIN says
  where the first one must land. Sequence 0 never carries a record.

### 4.2 Transcripts

```text
REGISTER   tag 'beignet/recovery/register/v1'
           signed by the recovery root
  PREFIX || STATE                the initial state: lease.epoch >= 1, a
                                 fresh writer key, the IMMUTABLE ORIGIN
                                 (fresh node: 1 and zeros; existing node:
                                 the retained base position), and a
                                 GENESIS LOGHEAD, always (registration
                                 never claims records the guardian does
                                 not hold; set replacement is a v1
                                 non-feature, 5.9)

RECORD     tag 'beignet/recovery/record/v1'
           signed by the writer key of lease.epoch
  PREFIX
  || recovery_id(32)
  || epoch(8)
  || sequence(8)
  || previousHash(32)
  || frameHash(32)
  || ciphertextHash(32)          SHA-256 of the record ciphertext

RECEIPT    tag 'beignet/recovery/receipt/v1'
           signed by the guardian
  PREFIX || guardianId(32) || STATE || issuedAt(8)

ACQUIRE    tag 'beignet/recovery/epoch-request/v1'
           signed TWICE: by the recovery root (authorizes the takeover)
           and by the NEW writer key (proves possession)
  PREFIX
  || STATE                       expectedState: the CAS guard, byte-exact
  || newEpoch(8)                 MUST equal expectedState.lease.epoch + 1
  || newWriterPublicKey(32)

TAKEOVER   tag 'beignet/recovery/takeover/v1'
           signed by the guardian
  PREFIX
  || guardianId(32)
  || STATE                       the superseded epoch's final state,
                                 immutable forever
  || newEpoch(8)
  || newWriterPublicKey(32)
  || issuedAt(8)
```

Receipts sign the complete STATE and are cumulative: a receipt whose
LOGHEAD carries sequence S certifies every stored record from
ORIGIN.firstSequence through S inclusive, across every intervening writer
epoch. Records below the origin do not exist for this namespace and no
receipt ever speaks for them.

What a receipt certifies, precisely: the guardian's canonical state AS OF
ISSUANCE. A record covered only by a MINORITY of receipts (fewer than
`required` distinct guardians) may later be removed from the canonical
log by a valid threshold-certified takeover that fixes an earlier final
head (5.7 truncation); such a receipt remains valid evidence that the
guardian acknowledged and stored the record, but not that the record
remains canonical. A record whose receipts reached the threshold can
never be superseded this way, because a takeover CAS against an earlier
state cannot assemble a quorum past it; that is the durability the
barrier discipline (spec 5.3) counts. Guardians MAY retain discarded
minority-tail records in an orphan archive for auditing, but MUST
exclude them from GET_STATE and from every STATE they sign. `ciphertextHash` binds the exact bytes of the
record at S, so retention is provable and attributable: a guardian cannot
claim to hold what it never stored, and a writer can prove which bytes a
receipt covered. `issuedAt` (unix milliseconds) is informational:
verification is content-based, receipts do not expire, and clock skew has
no protocol meaning.

## 5. Verb semantics

The per-node linearization rule from spec 5.5 governs REGISTER_NODE,
PUT_STATE, ACQUIRE_EPOCH and SYNC_EPOCH: one state machine per
recovery_id, no interleaving. A guardian makes the record, the updated
state, and the artifact it is about to return durable BEFORE the response
leaves.

### 5.1 REGISTER_NODE

Request: the REGISTER transcript fields plus the recovery root public key
(which IS recovery_id), the root signature, and `guardian_members`, the
committed member keys. The member list is REQUIRED: a guardian hosted by a
node (2.7) serves sets it never saw configured and learns the set from the
registration, and every guardian, configured or hosted, applies the same
check so the two cannot accept different registrations. Acceptance:

```text
guardian_members lists exactly `total` x-only keys, hashes (section 4)
to guardian_set_id, and names this guardian
recovery_id not yet registered for this guardian_set_id
root signature verifies over the REGISTER transcript under recovery_id
initial lease.epoch >= 1, writer key well-formed
ORIGIN.firstSequence >= 1 (fresh node: 1 with zero previousHash;
existing node: the retained base position)
LOGHEAD is genesis, always: a guardian never signs a receipt over a
head whose record it does not hold
```

The guardian persists the root-signed registration itself, durably,
alongside the state: it is the independently verifiable proof of which
origin was authorized, and GET_HEAD returns it (5.3), so a guardian
recovering from damaged storage, or a restore device, never has to infer
the origin from surviving records.

Response: a RECEIPT over the initial STATE. Idempotency: re-registering
the byte-identical initial state returns `OK_DUPLICATE` with the stored
receipt; any differing registration for an existing recovery_id is
`ERR_ALREADY_REGISTERED` (the stored state is returned so a legitimate
owner can reconcile).

### 5.2 PUT_STATE

Request: the RECORD transcript fields plus the ciphertext and writer
signature. Acceptance, atomically per the linearization rule:

```text
epoch == lease.epoch
writer signature verifies under lease.writerPublicKey
if logHead is genesis: sequence     == ORIGIN.firstSequence
                       previousHash == ORIGIN.previousHash
else:                  sequence     == logHead.sequence + 1
                       previousHash == logHead.frameHash
ciphertextHash == SHA-256(ciphertext)
ciphertext within advertised size limits
```

On accept, LOGHEAD advances to (sequence, frameHash, ciphertextHash,
epoch) and the response carries a RECEIPT over the new STATE.

Idempotency: re-submitting a record already stored byte-identically
returns `OK_DUPLICATE` with a current receipt. A DIFFERENT record at an
occupied (epoch, sequence) is `ERR_CONFLICT`: outside the crash-fault
model, never overwritten, and the guardian keeps the original and raises
an operator alarm.

Pipelining (spec 5.3): a writer MAY send multiple PUT_STATE requests
without waiting for responses. Each request receives its own response;
there is no batch request in v1. Because receipts are cumulative, a
client that only reads the last response of a pipelined burst has lost
nothing.

### 5.3 GET_HEAD

Request: recovery_id. Response: the guardian's current STATE, its
cumulative RECEIPT over that state, every TAKEOVER certificate it knows
for prior epochs of this namespace, and the stored root-signed
REGISTRATION (the origin proof, 5.1). Returning the bundle always
settles spec open question 11.7. A guardian whose store is uncertain
(spec 5.5 durability rules) sets `possibly_stale = true` and MUST still
refuse writes.

### 5.4 GET_STATE

Request: recovery_id, `from_sequence` (exclusive), `max_records`.
Response: up to `max_records` stored records in sequence order plus
`has_more`. Pagination is by sequence; no cursor state on the guardian.

### 5.5 ACQUIRE_EPOCH

Request: the ACQUIRE transcript fields plus both signatures. Acceptance,
atomically:

```text
recovery_id registered
root signature verifies under recovery_id
new-writer signature verifies under newWriterPublicKey
expectedState == the guardian's current STATE, byte-exact
newEpoch == expectedState.lease.epoch + 1
```

State transition on success:

```text
before:  lease = (E, KA)          logHead = (S, H, C, Er)
after:   lease = (E+1, KB)        logHead = (S, H, C, Er)   unchanged
         superseded final state (E, KA, S, H, C, Er) immutable forever
```

The response carries the TAKEOVER certificate over the superseded final
state AND a fresh RECEIPT over the new state, so GET_HEAD is coherent
from the first instant after takeover: the receipt covers the new lease
with the old log head, and the next record MUST be sequence S + 1 with
previousHash H, written under epoch E + 1.

On CAS mismatch: `ERR_CAS_FAILED` with the current STATE and known
certificates, so the caller refetches, reconciles (spec 5.7), repairs
lagging guardians (SYNC_RECORD), and retries.

Idempotency: repeating an acquisition for an epoch already bound to the
SAME newWriterPublicKey returns the stored certificate and receipt
(`OK_DUPLICATE`). The same epoch bound to a DIFFERENT key is
`ERR_EPOCH_SUPERSEDED`: first writer wins, the loser reconciles against
the returned state.

### 5.6 SYNC_RECORD

The PUT_STATE body relayed by ANYONE holding it; acceptance rules are
identical to 5.2 because records are self-authenticating. Used by restore
devices to repair lagging guardians before a CAS (spec 5.7 worked
example). Response: the guardian's cumulative RECEIPT after the append.

SYNC_RECORD only ever APPENDS at the guardian's current state; it never
inserts a historical record behind it and never crosses an epoch
boundary the guardian has not reached. A guardian missing or corrupting
HISTORY (a record from an epoch below its current lease) cannot be
patched in place: that is the uncertain-store case, repaired by the
rollback-and-replay procedure in 5.10.

### 5.7 SYNC_EPOCH

Request: a set of TAKEOVER certificates for one takeover. Exact
validation algorithm, in order, with the code each failure returns:

```text
1  every certificate carries identical protocol_version,
   guardian_set_id, recovery_id, superseded STATE, newEpoch and
   newWriterPublicKey                          else ERR_CERT_MISMATCH
2  guardian_set_id is served by this guardian  else ERR_UNKNOWN_SET
3  every guardianId is a MEMBER of the set committed by
   guardian_set_id, all distinct               else ERR_CERT_MISMATCH
4  every signature verifies over the TAKEOVER transcript under its
   guardianId                                  else ERR_BAD_SIGNATURE
5  distinct valid signers >= required (2 in crash-v1)
                                               else ERR_INSUFFICIENT_CERTS
6  newEpoch == certified STATE.lease.epoch + 1 else ERR_CERT_MISMATCH
7  local lease.epoch <= certified STATE.lease.epoch
   (a guardian already at or beyond newEpoch rejects the stale bundle)
                                               else ERR_EPOCH_REGRESSION
8  the local log contains the certified LOGHEAD (same sequence,
   frameHash, ciphertextHash); if the local log is BEHIND it, the
   guardian rejects and the submitter repairs it first through
   SYNC_RECORD                                 else ERR_HEAD_UNKNOWN
   a local record AT the certified sequence with a DIFFERENT hash is
   outside the crash-fault model               ERR_CONFLICT
```

On success the guardian adopts lease = (newEpoch, newWriterPublicKey),
fixes the superseded epoch's final state at the certified STATE, discards
any stored records of the superseded epoch ABOVE the certified LOGHEAD
(safe in quorum mode, spec 5.5), and responds `OK` with its own TAKEOVER
certificate (issued now if it never issued one) and a fresh RECEIPT.

### 5.8 INFO

`GET /beignet-guardian/v1/info` returns the InfoResponse message
(section 6): guardianId, supported protocol version range as integer
fields, the guardian_set_ids served, size limits, rate-limit hints, and
whether the guardian registers sets on demand (`accepts_registrations`, a
host per 2.7). A writer binding to a guardian requires its set to be listed
OR the guardian to accept registrations, since a host lists a set only once
REGISTER_NODE has run. Discovery only; nothing in INFO is signed or
load-bearing for safety.

### 5.9 Guardian-set replacement: UNSUPPORTED in protocol v1, literally

```text
Guardian-set replacement while journaled state is preserved is
UNSUPPORTED in protocol v1.

A node MUST NOT begin a journal for its recovery_id under a second
guardian set while any journaled state exists under a first. Exactly ONE
guardian set ever carries a given namespace's journal in v1.

Loss or replacement of the configured set degrades recovery to the
SCB/DLP path (Tier 1) until a channel-preserving ROTATE_SET exists in a
future protocol version.
```

The structural reasons, so nobody reintroduces a workaround: every
signed object carries its guardian_set_id inside the signed transcript,
so nothing from an old set can validate under a new one; writerEpoch and
sequence order states WITHIN one set and cannot order two independent
sets; peer_storage explicitly may return stale capsules, so after any
two-set period the Phase 3 restore selection (highest writerEpoch, then
sequence) can prefer a stale old-set capsule over a younger new-set one;
and nothing cryptographically fences the old set, because a stale device
holds the seed and therefore the recovery root, and could acquire
further old-set epochs. Only a root-signed monotonic set-generation
object ordered ABOVE (writerEpoch, sequence) can resolve that, and that
object is ROTATE_SET (old and new set ids, generations, the
quorum-certified final state, a migration snapshot anchor, retirement
semantics), reserved for a future protocol version rather than shipped
piecemeal.

What v1 DOES support, for clarity against the prohibition above:

- First-time enablement of guardians on an existing node is NOT a
  replacement: no prior set carries the namespace, the root-committed
  ORIGIN registered for it is the retained journal base with the
  journal's real sequence numbering (4.1), and Phase 3 capsule ordering
  stays monotonic across enablement because the node-wide journal
  numbering never resets.
- Replacing an individual FAILED guardian machine behind the SAME
  guardianId and set (restore its store, then repair through
  SYNC_RECORD and SYNC_EPOCH per 5.10) is operational maintenance, not
  set replacement.
- Abandoning guardians entirely (operator decision) is Tier 1
  degradation, stated in the box above.

### 5.10 Uncertain-store repair: rollback, then replay

The durability rules (spec 5.5) make a guardian that cannot prove its
store intact refuse writes until repaired. Repair semantics, exactly,
per namespace:

```text
1  the guardian identifies its LAST INTERNALLY CONSISTENT CHECKPOINT:
   the longest prefix of its stored records, takeover certificates and
   issued receipts that verifies completely, ANCHORED AT THE ROOT-SIGNED
   ORIGIN (chain continuity from ORIGIN.firstSequence and
   ORIGIN.previousHash, epoch continuity through its stored
   certificates, signatures). A surviving suffix of records that does
   not chain from the origin is NOT a checkpoint; without the stored
   registration itself, there is no checkpoint at all
2  it DISCARDS all per-namespace state after that checkpoint: records,
   lease changes, and its own issued receipts beyond it (receipts
   already handed out remain valid statements about what WAS stored;
   discarding the local copies does not and cannot revoke them)
3  it re-enters service in the checkpoint state, still refusing
   ordinary writes, flagged possibly_stale on reads
4  repair replays history in CHRONOLOGICAL order from the checkpoint:
   SYNC_RECORD for records under the lease epoch current at each point,
   SYNC_EPOCH for each takeover in sequence, then SYNC_RECORD again
   under the new epoch, and so on to the present
5  the guardian lifts possibly_stale and resumes accepting PUT_STATE
   and ACQUIRE_EPOCH ONLY when the replayed state exactly matches a
   target GuardianState supported by a valid THRESHOLD BUNDLE: receipts
   and takeover certificates from at least `required` DISTINCT
   guardians of the set, all covering that target. The artifacts are
   self-authenticating, so anyone may supply them, including retained
   copies from the writer or a restore device; what never suffices is
   writer POSSESSION alone. A writer replaying its own records and
   declaring its own head current could resurrect a superseded epoch on
   a rolled-back guardian and make it contradict a takeover certificate
   it issued before losing its store; fencing is permanent, so recency
   must be proven by quorum evidence, not asserted
6  when no quorum-certified target can be assembled, the guardian
   REMAINS read-only (possibly_stale) indefinitely, and recovery for
   the affected node degrades to the SCB/DLP path. Restrictive, and
   exactly the fencing guarantee this protocol exists to provide
```

This keeps the state machine strictly append-only: there is no
insert-behind-head operation anywhere in the protocol, and the epoch
acceptance rules of 5.2 and 5.7 hold unmodified at every step of the
replay, because the guardian's lease at each replay step is the lease
that was current at that point in history. A guardian at lease epoch 8
missing an epoch-7 record is exactly this case: it rolls back to its
last consistent state within epoch 7 (or earlier), replays the epoch-7
records, replays the 7 to 8 takeover through SYNC_EPOCH, and replays
forward.

## 6. Protobuf envelope

proto3. Field numbers are frozen forever; new fields append. The envelope
is TRANSPORT encoding only: signatures cover section 4 transcripts, never
these bytes. All keys are 32-byte x-only. Field presence: every bytes
field has an exact required length (32 or 64, ciphertext excepted) and a
wrong length is `ERR_MALFORMED`; uint64 zero is legal only where the
genesis LOGHEAD allows it (sequence 0, recordEpoch 0), and
`protocol_version = 0` or `epoch = 0` in a lease is `ERR_MALFORMED`.

```proto
syntax = "proto3";
package beignet.recovery.guardian.v1;

message Lease {
  uint64 epoch             = 1;
  bytes  writer_public_key = 2;  // 32
}

message LogHead {
  uint64 sequence        = 1;
  bytes  frame_hash      = 2;    // 32
  bytes  ciphertext_hash = 3;    // 32
  uint64 record_epoch    = 4;
}

message ChainOrigin {
  uint64 first_sequence = 1;     // >= 1
  bytes  previous_hash  = 2;     // 32; zeros for a fresh node
}

message GuardianState {
  bytes       recovery_id = 1;   // 32
  Lease       lease       = 2;
  ChainOrigin origin      = 3;   // immutable, root-committed at registration
  LogHead     log_head    = 4;
}

message Record {
  uint32 protocol_version = 1;
  bytes  guardian_set_id  = 2;   // 32
  bytes  recovery_id      = 3;   // 32
  uint64 epoch            = 4;
  uint64 sequence         = 5;
  bytes  previous_hash    = 6;   // 32
  bytes  frame_hash       = 7;   // 32
  bytes  ciphertext       = 8;   // opaque AEAD bytes, section 3.2 layout
  bytes  writer_signature = 9;   // 64, BIP340 over the RECORD transcript
}

message Receipt {
  uint32        protocol_version = 1;
  bytes         guardian_set_id  = 2;
  bytes         guardian_id      = 3;  // 32
  GuardianState state            = 4;
  uint64        issued_at        = 5;
  bytes         signature        = 6;  // 64, over the RECEIPT transcript
}

message TakeoverCertificate {
  uint32        protocol_version      = 1;
  bytes         guardian_set_id       = 2;
  bytes         guardian_id           = 3;
  GuardianState superseded_state      = 4;
  uint64        new_epoch             = 5;
  bytes         new_writer_public_key = 6;  // 32
  uint64        issued_at             = 7;
  bytes         signature             = 8;  // 64, over the TAKEOVER transcript
}

message RegisterNodeRequest {
  uint32        protocol_version = 1;
  bytes         guardian_set_id  = 2;
  GuardianState initial_state    = 3;
  bytes         root_signature   = 4;  // 64, over the REGISTER transcript
  repeated bytes guardian_members = 5; // 32 each; exactly `total`; REQUIRED
}
message RegisterNodeResponse {
  uint32        status  = 1;
  string        detail  = 2;
  Receipt       receipt = 3;           // OK, OK_DUPLICATE
  GuardianState current = 4;           // ERR_ALREADY_REGISTERED
}

message PutStateRequest  { Record record = 1; }
message PutStateResponse {
  uint32        status  = 1;
  string        detail  = 2;
  Receipt       receipt = 3;           // OK, OK_DUPLICATE
  GuardianState current = 4;           // sequencing and epoch errors
}

message GetHeadRequest {
  uint32 protocol_version = 1;
  bytes  guardian_set_id  = 2;
  bytes  recovery_id      = 3;
}
message GetHeadResponse {
  uint32        status         = 1;
  string        detail         = 2;
  GuardianState state          = 3;
  Receipt       receipt        = 4;
  repeated TakeoverCertificate certificates = 5;
  bool          possibly_stale = 6;
  RegisterNodeRequest registration = 7; // the stored origin proof (5.1)
}

message GetStateRequest {
  uint32 protocol_version = 1;
  bytes  guardian_set_id  = 2;
  bytes  recovery_id      = 3;
  uint64 from_sequence    = 4;
  uint32 max_records      = 5;
}
message GetStateResponse {
  uint32 status   = 1;
  string detail   = 2;
  repeated Record records = 3;
  bool   has_more = 4;
  bool   possibly_stale = 5;
}

message AcquireEpochRequest {
  uint32        protocol_version      = 1;
  bytes         guardian_set_id       = 2;
  GuardianState expected_state        = 3;
  uint64        new_epoch             = 4;
  bytes         new_writer_public_key = 5;  // 32
  bytes         root_signature        = 6;  // 64, over the ACQUIRE transcript
  bytes         new_writer_signature  = 7;  // 64, over the ACQUIRE transcript
}
message AcquireEpochResponse {
  uint32              status      = 1;
  string              detail      = 2;
  TakeoverCertificate certificate = 3;  // OK, OK_DUPLICATE
  Receipt             receipt     = 4;  // OK, OK_DUPLICATE
  GuardianState       current     = 5;  // ERR_CAS_FAILED, ERR_EPOCH_SUPERSEDED
  repeated TakeoverCertificate certificates = 6;
}

message SyncRecordRequest  { Record record = 1; }
message SyncRecordResponse {
  uint32        status  = 1;
  string        detail  = 2;
  Receipt       receipt = 3;
  GuardianState current = 4;
}

message SyncEpochRequest  { repeated TakeoverCertificate certificates = 1; }
message SyncEpochResponse {
  uint32              status      = 1;
  string              detail      = 2;
  TakeoverCertificate certificate = 3;
  Receipt             receipt     = 4;
  GuardianState       current     = 5;
}

message InfoResponse {
  bytes  guardian_id          = 1;  // 32
  uint32 min_protocol_version = 2;
  uint32 max_protocol_version = 3;
  repeated bytes guardian_set_ids = 4;
  uint64 max_ciphertext_bytes = 5;
  uint32 max_records_per_get  = 6;
  uint32 rate_limit_per_minute = 7; // 0 = unspecified
  uint32 accepts_registrations = 8; // 1: a host that registers sets on
                                    // demand (2.7); the set appears in
                                    // guardian_set_ids only after
                                    // REGISTER_NODE. A configured guardian
                                    // omits it and always lists its set
}
```

Per-status field rules: `receipt` and `certificate` fields are present
EXACTLY on `OK` and `OK_DUPLICATE`; `current` is present exactly on the
statuses annotated above and absent otherwise; `detail` is never
load-bearing. Implementations without a protobuf dependency (browser and
React Native ports) may use any conformant proto3 encoder; the messages
use only scalar, bytes and simple nested fields so a minimal hand-rolled
codec stays tractable, and signatures never depend on the envelope.

## 7. Status codes

```text
0   OK
1   OK_DUPLICATE            idempotent replay; stored artifacts returned
10  ERR_UNSUPPORTED_VERSION protocol_version outside the advertised range
11  ERR_MALFORMED           missing field, wrong length, undecodable body,
                            zero where zero is not legal (section 6)
12  ERR_UNKNOWN_NODE        recovery_id not registered (2.6)
13  ERR_UNKNOWN_SET         guardian_set_id not served by this guardian
14  ERR_ALREADY_REGISTERED  differing registration for an existing
                            recovery_id; current state attached
20  ERR_EPOCH_SUPERSEDED    write or acquire from a fenced epoch;
                            current state and certificates attached
21  ERR_SEQUENCE_GAP        sequence != logHead.sequence + 1 (or, for the
                            first record of a genesis namespace,
                            != ORIGIN.firstSequence); current state
                            attached
22  ERR_PREV_HASH_MISMATCH  previousHash != logHead.frameHash (or, for
                            the first record, != ORIGIN.previousHash)
23  ERR_BAD_SIGNATURE       writer, root, new-writer, or certificate
                            signature failed
24  ERR_CAS_FAILED          expectedState != stored state; current state
                            and certificates attached
25  ERR_CONFLICT            different record at an occupied (epoch,
                            sequence), or a certified head conflicting
                            with a stored record; crash-fault model
                            breach; the guardian keeps the original and
                            alarms
26  ERR_INSUFFICIENT_CERTS  SYNC_EPOCH below the required threshold
27  ERR_CERT_MISMATCH       SYNC_EPOCH certificates disagree, carry
                            non-members, or violate epoch continuity
28  ERR_EPOCH_REGRESSION    SYNC_EPOCH bundle older than local state
29  ERR_HEAD_UNKNOWN        SYNC_EPOCH certified head not in the local
                            log; repair with SYNC_RECORD first
30  ERR_STORE_UNCERTAIN     durability rules force write refusal until
                            repaired (spec 5.5)
31  ERR_RATE_LIMITED        semantic rate limit; retry_after in detail
                            AND the Retry-After HTTP header
32  ERR_TOO_LARGE           object exceeds the guardian's advertised limit
33  ERR_QUOTA_EXCEEDED      a hosted guardian's storage quota is exhausted
                            for new namespaces or further records; not a
                            transport condition and not retryable until the
                            operator raises the quota (2.7)
50  ERR_INTERNAL            transient guardian fault; safe to retry
```

Writers treat 20, 24, and 25 as reconciliation or freeze signals per spec
5.6, never as retryable transport noise.

## 8. Sizes and limits

```text
record ciphertext           <= 16 MiB hard protocol cap; guardians MAY
                               advertise lower limits in INFO and writers
                               MUST respect them (snapshot frames are the
                               large case; delta frames stay small under
                               the journal's byte cadence)
GET_STATE max_records       <= 256 per request
request body                ciphertext cap plus 4 KiB envelope
certificates per SYNC_EPOCH <= total guardians in the set
```

## 9. Authentication, replay, and anti-DoS

Every mutating verb is semantically idempotent: replaying a captured
request either returns the stored artifact (`OK_DUPLICATE`) or a
deterministic rejection. There are no session nonces: records and
requests are self-authenticating, and replays cannot advance, roll back,
or fork state. Transport capture is therefore a privacy concern only, and
both normative transports encrypt.

Transport authentication is MANDATORY for every non-local deployment:
onion-http guardians require Tor v3 client authorization or an
operator-issued credential; https guardians require an operator-issued
credential (bearer token or macaroon in the Authorization header) and
rate limiting. Running open is reserved for local development and
local-http. This is anti-DoS and privacy hardening ON TOP of the
recovery_id namespace (1.1); none of it participates in record
acceptance, which rests entirely on the signatures (spec 5.5).

## 10. Version negotiation

The client sends `protocol_version` in every request; the guardian
advertises `min_protocol_version` and `max_protocol_version` in
InfoResponse and rejects outside the range with
`ERR_UNSUPPORTED_VERSION`. Version 1 is this document. Breaking
transcript changes REQUIRE a new version AND new domain-separation tags
(the /v1 suffix in every tag), so cross-version signature confusion is
structurally impossible.
