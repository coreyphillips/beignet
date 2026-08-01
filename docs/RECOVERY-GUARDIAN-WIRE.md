# Beignet Recovery Guardian Wire Specification

Version 1 (protocol_version = 1). Companion to docs/RECOVERY-PROTOCOL.md
sections 5.5 to 5.7; this document fixes the exact bytes. The semantic
invariants (per-node linearization, durability before acknowledgment,
cumulative receipts, CAS takeover, backfill) are normative THERE; nothing in
this document relaxes them. Where the two disagree, RECOVERY-PROTOCOL.md
wins and this document has a bug.

Decision context: section 12.1 of RECOVERY-PROTOCOL.md records the transport
and architecture decisions this wire format implements (onion-HTTP and
clearnet HTTPS as first-class transports, no BOLT 8 in v1, the crash-v1
profile, canonical signed transcripts, the VSS-sibling stance).

Style: no em-dashes anywhere, per the repo rule.

---

## 1. Roles and objects

A guardian is a minimal blob store with one nontrivial duty: signed,
monotonic, cumulative receipts (spec 5.5). It never decrypts record
ciphertext. Verbs:

```text
PUT_STATE       append one record for (nodeId, epoch); returns a receipt
GET_HEAD        current head + takeover certificates + receipt set
GET_STATE       fetch stored records, paginated
ACQUIRE_EPOCH   CAS takeover; returns a takeover certificate
SYNC_RECORD     relay an already-signed record to a lagging guardian
SYNC_EPOCH      present takeover certificates to a guardian that missed one
INFO            capability discovery (transports carry it; not a verb)
```

Acceptance is record-level, never connection-level: a record is valid
because its writer signature, epoch binding, and chain position verify.
Transport authentication exists for anti-DoS and privacy only (spec 5.5).

## 2. Transports

Two first-class, normative transports (spec 12.1). The signed objects in
this document never embed URLs or transport details, so the same bytes ride
either transport, a LAN connection, or a future BOLT 8 adapter.

### 2.1 onion-http

HTTP/1.1 over a Tor v3 onion service. TLS is NOT required: the onion
service provides end-to-end encryption and authenticates the service
through the address itself. Guardians SHOULD bind their HTTP listener to
127.0.0.1 and publish it via HiddenServicePort. Private guardians MAY
require Tor v3 client authorization.

### 2.2 https

HTTP/1.1 or HTTP/2 over TLS 1.2 or newer. Certificate validation is
MANDATORY; plaintext HTTP on clearnet is forbidden. A Tor-only wallet MAY
reach an https-only guardian through an exit relay (the payload stays
TLS-protected; the destination is visible to the exit), but wallets with
Tor enabled MUST prefer an onion endpoint when the guardian advertises one.

### 2.3 local-http

Plain HTTP on 127.0.0.1 or an operator-controlled LAN address (the Umbrel
local-guardian deployment). The operator's machine is the trust domain;
this transport MUST NOT be offered across untrusted networks.

### 2.4 Endpoint descriptors

Guardians are addressed by descriptor (the capsule's GuardianDescriptor,
spec 5.4):

```json
{
  "guardianId": "02abc...",
  "transports": [
    { "type": "onion-http", "url": "http://<56-char-v3>.onion" },
    { "type": "https", "url": "https://guardian.example.com" }
  ]
}
```

Selection rule: Tor enabled -> first onion-http endpoint; otherwise first
https endpoint; local-http only when explicitly configured. A descriptor
with no usable transport is an error surfaced to the operator, never a
silent skip.

### 2.5 HTTP mapping

Every verb is `POST /beignet-guardian/v1/<verb-lowercase>` with
`Content-Type: application/x-protobuf` and a protobuf body (section 6).
Discovery is `GET /beignet-guardian/v1/info`. HTTP status is 200 for every
well-formed protocol exchange, INCLUDING protocol-level rejections; the
protocol result lives in the response body's `status` field (section 7).
Non-200 statuses mean the HTTP layer itself failed (404 wrong path, 413
body over the advertised limit, 429 transport-level rate limit with
Retry-After, 5xx guardian down).

## 3. Cryptography

- Hash: SHA-256 everywhere.
- Signatures: BIP340 Schnorr over secp256k1, 64 bytes, over a BIP340
  tagged hash of a canonical transcript (section 4). Protobuf bytes are
  NEVER signed: protobuf serialization is not canonical (spec 12.1).
- Record ciphertext AEAD: AES-256-GCM exactly as stored by the journal
  (spec 5.3): `iv(12) || authTag(16) || ciphertext`, per-epoch key, AAD
  binding (nodeId, writerEpoch, sequence, previousFrameHash). The guardian
  treats it as opaque bytes. Uniform AES-256-GCM settles open question
  11.2: one AEAD across storage, journal, capsule, and guardian records.
- Keys:
  - `nodeId`: the node's identity public key, 33 bytes compressed.
  - Writer keys are FRESH RANDOM secp256k1 keypairs generated at each
    epoch acquisition, x-only 32-byte public form in transcripts, 33-byte
    compressed on the wire. Never the node identity key and never derived
    from the seed: a superseded device's writer key must die with it, and
    the seed alone must not be able to forge records for old epochs.
  - `guardianId`: the guardian's long-lived signing public key, 33 bytes
    compressed. Receipt-key rotation is out of scope for v1 (open
    question 11.6 stays open); a rotated guardian is a new guardianId and
    therefore a new guardian set.

## 4. Canonical transcripts and domain separation

All multi-byte integers are unsigned big-endian, fixed width. All signed
objects begin implicitly with the protocol version and the guardian set:

```text
PREFIX = protocol_version(2) || guardian_set_id(32)
```

`guardian_set_id` commits to the set and its policy:

```text
guardian_set_id = TaggedHash("beignet/recovery/guardian-set/v1",
    profile_id(2)
    || required(2)
    || total(2)
    || sorted_ascending(guardianId_1(33) .. guardianId_n(33)))
```

Profile `crash-v1` is `profile_id = 1`, `required = 2`, `total = 3`. It is
the ONLY profile in v1 (spec 12.1: named profiles, no free-form quorum
tuples). The encoding carries the fields anyway so a future Byzantine
profile (for example 3-of-4) slots in without a wire break.

Transcripts, each hashed with its own BIP340 tag and then signed:

```text
RECORD          tag "beignet/recovery/record/v1", signed by the writer key
  PREFIX
  || nodeId(33)
  || epoch(8)
  || sequence(8)
  || previousHash(32)
  || frameHash(32)
  || ciphertextHash(32)          SHA-256 of the record ciphertext

HEAD            embedded in receipts and certificates, never signed alone
  nodeId(33)
  || epoch(8)
  || writerPublicKey(33)
  || sequence(8)
  || frameHash(32)

RECEIPT         tag "beignet/recovery/receipt/v1", signed by the guardian
  PREFIX
  || guardianId(33)
  || HEAD
  || ciphertextHash(32)
  || issuedAt(8)                 unix milliseconds, informational

ACQUIRE         tag "beignet/recovery/epoch-request/v1", signed by the NEW
                writer key (proves possession)
  PREFIX
  || nodeId(33)
  || HEAD                        expectedHead: the CAS guard
  || newEpoch(8)                 MUST equal expectedHead.epoch + 1
  || newWriterPublicKey(33)

TAKEOVER        tag "beignet/recovery/takeover/v1", signed by the guardian
  PREFIX
  || guardianId(33)
  || HEAD                        takeoverHead: the superseded epoch's
                                 now-immutable final head
  || newEpoch(8)
  || newWriterPublicKey(33)
  || issuedAt(8)
```

Receipts are cumulative (spec 5.5): a receipt whose HEAD carries sequence S
certifies every record at or below S in that epoch. `ciphertextHash` in the
receipt binds the exact ciphertext of the record at S, so retention is
provable and attributable (spec 12.1): a guardian cannot claim to hold what
it never stored, and a writer can prove which bytes a receipt covered.

`issuedAt` is informational: verification is content-based, receipts do not
expire, and clock skew has no protocol meaning.

## 5. Verb semantics

The per-node linearization rule from spec 5.5 governs every verb: PUT_STATE
and ACQUIRE_EPOCH for one nodeId run through a single state machine, and a
guardian makes the record, head, epoch state, and the artifact it is about
to return durable BEFORE the response leaves.

### 5.1 PUT_STATE

Request carries the full record (fields of the RECORD transcript plus the
ciphertext and the writer signature). Acceptance rules are spec 5.5
verbatim: current epoch, bound writer key, verifying signature, sequence
continuity, previous-hash linkage. Response: a RECEIPT.

Idempotency: re-submitting a record that is already stored byte-identically
(same epoch, sequence, frameHash, ciphertextHash) returns `OK_DUPLICATE`
with the stored receipt. A DIFFERENT record at an occupied (epoch,
sequence) is `ERR_CONFLICT`: outside the crash-fault model, never
overwritten, and the guardian keeps the original.

Pipelining (spec 5.3): a writer MAY stream records without waiting for
receipts; the guardian processes them in order and MAY reply with only the
latest cumulative receipt for a batch.

### 5.2 GET_HEAD

Request: nodeId. Response: the guardian's current HEAD, every
TakeoverCertificate it knows for prior epochs of this node, and its
cumulative receipt for the current head. Returning the receipt bundle
always (not on request) settles open question 11.7: the bundle is one
receipt plus at most one certificate per superseded epoch, small enough
that a second round trip is never worth it. A guardian whose store is
uncertain (spec 5.5 durability rules) sets `possibly_stale = true` and
MUST still refuse writes.

### 5.3 GET_STATE

Request: nodeId, `from_sequence` (exclusive), `max_records`. Response: up
to `max_records` stored records in sequence order plus a `has_more` flag.
Pagination is by sequence; there is no cursor state on the guardian.

### 5.4 ACQUIRE_EPOCH

Request: the ACQUIRE transcript fields plus the new-writer signature.
Acceptance is the CAS from spec 5.5: `expectedHead` must equal the stored
head exactly and `newEpoch` must be `expectedHead.epoch + 1`. On success
the guardian binds the epoch to `newWriterPublicKey`, fixes the superseded
epoch's final head forever, and returns a TAKEOVER certificate. On
mismatch: `ERR_CAS_FAILED` with the current head (and certificates), so
the caller refetches, reconciles (spec 5.7), and retries.

Idempotency: repeating an ACQUIRE_EPOCH for an epoch already bound to the
SAME newWriterPublicKey returns the stored certificate (`OK_DUPLICATE`).
The same epoch with a DIFFERENT key is `ERR_EPOCH_SUPERSEDED`: first
writer wins, the loser reconciles against the returned head.

### 5.5 SYNC_RECORD

The PUT_STATE body relayed by ANYONE holding it; acceptance rules are
identical (records are self-authenticating). Used by restore devices to
repair lagging guardians before a CAS (spec 5.7 worked example). Response
is the guardian's cumulative receipt after the append.

### 5.6 SYNC_EPOCH

Request: a set of TAKEOVER certificates for one takeover. The guardian
verifies at least `required` distinct guardian signatures from the set
committed by `guardian_set_id`, adopts the new epoch and writer key, fixes
the superseded epoch's final head at `takeoverHead`, and discards any
stored records of the superseded epoch above it (safe in quorum mode, spec
5.5). Response: `OK` and the guardian's own TAKEOVER certificate for its
records (issued now if it never issued one).

### 5.7 INFO

`GET /beignet-guardian/v1/info` returns: guardianId, supported
protocol_version range, the guardian_set_ids it serves, per-object and
per-request size limits (section 8), and rate-limit hints. Discovery only;
nothing in INFO is signed or load-bearing for safety.

## 6. Protobuf envelope

proto3. Field numbers are frozen forever; new fields append. The envelope
is TRANSPORT encoding only: signatures cover section 4 transcripts, never
these bytes.

```proto
syntax = "proto3";
package beignet.recovery.guardian.v1;

message Head {
  bytes  node_id           = 1;  // 33 bytes
  uint64 epoch             = 2;
  bytes  writer_public_key = 3;  // 33 bytes
  uint64 sequence          = 4;
  bytes  frame_hash        = 5;  // 32 bytes
}

message Record {
  uint32 protocol_version  = 1;
  bytes  guardian_set_id   = 2;  // 32 bytes
  bytes  node_id           = 3;
  uint64 epoch             = 4;
  bytes  writer_public_key = 5;
  uint64 sequence          = 6;
  bytes  previous_hash     = 7;
  bytes  frame_hash        = 8;
  bytes  ciphertext        = 9;  // opaque AEAD bytes, spec 5.3 layout
  bytes  writer_signature  = 10; // BIP340 over the RECORD transcript
}

message Receipt {
  uint32 protocol_version = 1;
  bytes  guardian_set_id  = 2;
  bytes  guardian_id      = 3;
  Head   head             = 4;
  bytes  ciphertext_hash  = 5;
  uint64 issued_at        = 6;
  bytes  signature        = 7;  // BIP340 over the RECEIPT transcript
}

message TakeoverCertificate {
  uint32 protocol_version    = 1;
  bytes  guardian_set_id     = 2;
  bytes  guardian_id         = 3;
  Head   takeover_head       = 4;
  uint64 new_epoch           = 5;
  bytes  new_writer_public_key = 6;
  uint64 issued_at           = 7;
  bytes  signature           = 8; // BIP340 over the TAKEOVER transcript
}

message PutStateRequest   { Record record = 1; }
message GetHeadRequest    { uint32 protocol_version = 1; bytes guardian_set_id = 2; bytes node_id = 3; }
message GetStateRequest   { uint32 protocol_version = 1; bytes guardian_set_id = 2; bytes node_id = 3; uint64 from_sequence = 4; uint32 max_records = 5; }
message AcquireEpochRequest {
  uint32 protocol_version    = 1;
  bytes  guardian_set_id     = 2;
  bytes  node_id             = 3;
  Head   expected_head       = 4;
  uint64 new_epoch           = 5;
  bytes  new_writer_public_key = 6;
  bytes  new_writer_signature  = 7; // BIP340 over the ACQUIRE transcript
}
message SyncRecordRequest  { Record record = 1; }
message SyncEpochRequest   { repeated TakeoverCertificate certificates = 1; }

message GuardianResponse {
  uint32 status         = 1;  // section 7
  string detail         = 2;  // human-readable, never load-bearing
  Head   current_head   = 3;  // on ERR_CAS_FAILED, ERR_EPOCH_SUPERSEDED,
                              // ERR_SEQUENCE_GAP, and every GET_HEAD
  Receipt receipt       = 4;  // PUT_STATE, SYNC_RECORD, GET_HEAD
  repeated TakeoverCertificate certificates = 5;
  repeated Record records = 6; // GET_STATE
  bool   has_more       = 7;  // GET_STATE
  bool   possibly_stale = 8;  // reads from an uncertain store
  uint32 retry_after_seconds = 9; // ERR_RATE_LIMITED
}
```

Implementations without a protobuf dependency (browser and React Native
ports) may use any conformant proto3 encoder; the messages above use only
scalar and bytes fields precisely so a minimal hand-rolled codec stays
tractable. Canonical transcripts, not protobuf bytes, are what get signed,
so encoder variance cannot break verification.

## 7. Status codes

```text
0   OK
1   OK_DUPLICATE            idempotent replay; stored artifact returned
10  ERR_UNSUPPORTED_VERSION protocol_version outside the advertised range
11  ERR_MALFORMED           missing field, wrong length, undecodable body
12  ERR_UNKNOWN_NODE        GET/ACQUIRE for a nodeId never stored
13  ERR_UNKNOWN_SET         guardian_set_id not served by this guardian
20  ERR_EPOCH_SUPERSEDED    write or acquire from a fenced epoch;
                            current_head and certificates attached
21  ERR_SEQUENCE_GAP        sequence != stored + 1; current_head attached
22  ERR_PREV_HASH_MISMATCH  previousHash != stored frameHash
23  ERR_BAD_SIGNATURE       writer, new-writer, or certificate signature
24  ERR_CAS_FAILED          expectedHead != stored head; current_head and
                            certificates attached for reconciliation
25  ERR_CONFLICT            different record at an occupied (epoch,
                            sequence); crash-fault model breach; the
                            guardian keeps the original and alarms
26  ERR_INSUFFICIENT_CERTS  SYNC_EPOCH below the required threshold
30  ERR_STORE_UNCERTAIN     durability rules force write refusal until
                            repaired (spec 5.5)
31  ERR_RATE_LIMITED        semantic rate limit; retry_after_seconds set
32  ERR_TOO_LARGE           object exceeds the guardian's advertised limit
50  ERR_INTERNAL            transient guardian fault; safe to retry
```

Writers treat 20, 24, and 25 as reconciliation or freeze signals per spec
5.6, never as retryable transport noise.

## 8. Sizes and limits

```text
record ciphertext        <= 16 MiB hard protocol cap; guardians MAY
                            advertise lower limits in INFO and writers
                            MUST respect them (snapshot frames are the
                            large case; delta frames stay small under the
                            journal's byte cadence)
GET_STATE max_records    <= 256 per request
request body             record ciphertext cap plus 4 KiB envelope
certificates per SYNC_EPOCH <= total guardians in the set
```

## 9. Replay, idempotency, and anti-DoS summary

Every mutation verb is semantically idempotent (spec 12.1): replaying a
captured request either returns the stored artifact (`OK_DUPLICATE`) or a
deterministic rejection. There are no session nonces and no
challenge-response: records and requests are self-authenticating, and
replays cannot advance, roll back, or fork state. Consequently transport
capture is a privacy concern only, and both normative transports already
encrypt.

Anti-DoS is transport-layer and deployment-specific: onion client
authorization, HTTPS-level tokens (bearer or macaroon) issued by the
guardian operator, IP rate limits. None of it participates in record
acceptance (spec 5.5), so a deployment may run entirely open if its
operator accepts the load.

## 10. Version negotiation

The client sends `protocol_version` in every request; the guardian
advertises `min_version` and `max_version` in INFO and rejects outside the
range with `ERR_UNSUPPORTED_VERSION` plus its range in `detail`. Version 1
is this document. Breaking transcript changes REQUIRE a new version AND
new domain-separation tags (the `/v1` suffix in every tag), so cross
-version signature confusion is structurally impossible.
