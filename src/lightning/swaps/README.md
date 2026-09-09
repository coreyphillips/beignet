# Swap foundations

`import { swaps } from 'beignet/lightning'` exposes P2WSH contract construction,
signed claim/refund transactions, verified preimage extraction and pure admission
checks. These primitives are the first implementation phase of
[issue 737](https://github.com/coreyphillips/beignet/issues/737). They do not run a
swap provider, hold invoices, pay invoices, fund outputs, persist a swap or
broadcast a transaction.

## Contract and transaction invariants

The same contract works for either direction; claim and refund identify the
on-chain signing roles:

```text
OP_IF
    OP_SIZE 32 OP_EQUALVERIFY
    OP_SHA256 <paymentHash> OP_EQUALVERIFY
    <claimPublicKey> OP_CHECKSIG
OP_ELSE
    <refundHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <refundPublicKey> OP_CHECKSIG
OP_ENDIF
```

`buildSwapHtlc` accepts a 32-byte SHA256 payment hash, valid compressed secp256k1
public keys and an integer refund height from 1 through 499,999,999. It returns the
witness script, P2WSH output script and address for the supplied Bitcoin network
(mainnet by default). The preimage length is enforced by Script, including when
a shorter or longer secret hashes to the committed payment hash.

The claim witness is `[signature, preimage, 01, witnessScript]`. The refund
witness is `[signature, empty, witnessScript]`. **The preimage branch has no
expiry.** Reaching the refund height enables a competing spend; it does not
disable claims. CLTV and transaction finality are defined in
[BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).

`buildSwapClaimTx` and `buildSwapRefundTx` each take the full funding transaction,
its output index, the contract terms, an absolute fee in satoshis, a destination
script and the branch's private key. They verify the selected funding script
against the canonical contract and derive the input value and outpoint from
that transaction. Funding values and fees must be positive integers within
Bitcoin's money range; a wrong branch key is refused.

Both builders produce one input, one output, version 2, sequence `0xfffffffd`
and a low-S ECDSA `SIGHASH_ALL` signature using
[BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki). The claim
uses locktime zero. The refund uses locktime `refundHeight`, so its first
eligible block is **refundHeight + 1**. A refund can be prepared before maturity.
Sequence enables CLTV and fee replacement without introducing a relative lock.

Destinations are limited to native P2WPKH, P2WSH and P2TR scripts. The retained
output must be at least 294 sat for P2WPKH or 330 sat for P2WSH/P2TR. These are
conventional dust floors for
[Bitcoin Core's 3,000 sat/kvB dust relay policy](https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.cpp), not fee estimates or
guarantees of relay under every node's settings. Callers must select appropriate
fees and validate destination ownership themselves. Fee replacement is possible
by rebuilding and signing, but no fee management service is included.

```ts
import * as bitcoin from 'bitcoinjs-lib';
import { swaps } from 'beignet/lightning';

// contract, fundingHex, claimKey, preimage and destinationScript come from
// authenticated local swap state. Confirm funding with a trusted chain source.
const funding = {
    htlc: contract,
    fundingTransaction: bitcoin.Transaction.fromHex(fundingHex),
    outputIndex: 0
};
const claim = swaps.buildSwapClaimTx({
    ...funding,
    destinationScript,
    feeSatoshis: 1_000n,
    privateKey: claimKey,
    preimage
});
```

`extractSwapPreimage(transaction, funding)` returns a copy of the preimage only
for the exact expected output, canonical script and minimal claim selector,
matching 32-byte hash preimage, and valid low-S claim signature bound to the
funding value. Extraction supports `SIGHASH_ALL`, `SIGHASH_NONE` and
`SIGHASH_SINGLE`, each optionally combined with `SIGHASH_ANYONECANPAY`, because
the claimant can choose any of these independently of the builders' defaults.
It locates the input even in a multi-input
transaction and refuses duplicate spends of the expected output. Unrelated,
malformed, refund or invalidly signed witnesses return `undefined`. Invalid
expected funding data throws. Undefined sighash values and other script forms
are outside this API.

Extraction is not a transaction consensus validator or proof of publication,
inclusion, unspentness or confirmations. Validate chain status separately. Do not
treat a caller-supplied funding transaction or observed spending transaction as
trusted merely because these helpers accepted it.

**An `undefined` result does not establish that the preimage was never
revealed.** A preimage can also become known through an invalid transaction,
an unsupported witness or an off-chain message. A future provider must retain
every hash-matching preimage it learns and separately establish the winning
on-chain resolution; it must never cancel a held payment merely because this
helper returned `undefined`.

## Direction-specific admission

All time inputs are block heights/counts. There are no default safety margins;
operators must derive budgets for their chain, fee policy, confirmation/reorg
policy and Lightning behavior. Equality at the outer deadline is refused to
leave a full-block boundary.

| Direction | Provider's role | Required order |
| --- | --- | --- |
| Submarine | Pays Lightning, claims client's BTC | `refundHeight > latestOutgoingHtlcExpiry + claimSafetyBlocks` |
| Reverse | Holds Lightning, funds BTC for client | `earliestIncomingExpiry - holdCancelSafetyBlocks > refundHeight + resolutionSafetyBlocks` |

`validateSubmarineSwapAdmission` also requires funding to meet an explicitly
positive confirmation requirement and the outgoing expiry bound to remain in
the future. `latestOutgoingHtlcExpiry` must be an **enforced maximum across every
attempt and MPP part**. A wall-clock `payInvoice` timeout is not that bound, and
does not prove that outgoing HTLCs failed. The claim margin must include enough
time to obtain a late preimage and confirm the provider's claim.

`validateReverseSwapAdmission` checks an exact full invoice amount across unique,
positive committed HTLC parts with the expected payment hash. The parts must be
irrevocably committed according to authoritative local channel state, with
channel-id/HTLC-id identifiers; this function cannot establish commitment from
caller-supplied data. The earliest part expiry controls the budget, including
the Lightning node's actual early automatic hold cancellation margin. The helper
also requires `refundHeight > currentHeight + fundingSafetyBlocks`. It returns
the earliest effective cancellation height only as a planning bound.

`resolutionSafetyBlocks` must cover the first eligible refund block, confirmation
and reorg policy, and time to settle Lightning after a competing claim reveals
the preimage. Funding must never be admitted on an individual hold event when
the invoice has only a partial MPP amount.

**Admission is not permission to cancel a reverse hold.** A refund deadline,
payment timeout or refund broadcast is insufficient. A future engine must keep
the hold and chain observer coordinated until it has durably recorded the
winning on-chain resolution with its configured confirmation/reorg policy. It
must handle late claims, including claims racing a replacement refund. If the
node can automatically cancel before that resolution, funding must be refused.
No finite margin guarantees safety through arbitrary chain stalls or deep
reorganizations; the engine needs an explicit risk policy and operational limits.

## Phase 2 primitives

The second phase of issue 737 adds the pieces a provider engine builds on,
still without running a swap:

- **Committed held-invoice snapshot.** `LightningNode.getHeldInvoiceSnapshot`
  returns every parked part of a hold invoice with its channel/HTLC identity,
  its absolute expiry read from the channel's own entry, whether the channel
  still holds it COMMITTED, the invoice's declared total, and `cancelHeight`,
  the first height at which the node's own CLTV sweeper
  (`HELD_HTLC_EXPIRY_MARGIN`, exported) would cancel the hash. `complete` is
  the only admission signal for a reverse swap; the per-part `htlc:held`
  event is not. Every cancel path emits `hold:cancelled` with its reason.
- **Absolute outgoing expiry ceiling.** `sendPaymentWithOptions` (and the
  positional `sendPayment`) take `maxCltvExpiryHeight`. The route search is
  bounded by it and the dispatch gate refuses, before any HTLC is added, an
  attempt, retry or MPP part whose wire expiry would exceed it, including
  after a height-skew retry raised the base height. `getOutgoingHtlcs` and
  `awaitPaymentResolution` report what the HTLCs actually did: a wall-clock
  `failPayment` never makes a payment `resolved` while an HTLC is live, and
  `payment:preimage` announces a preimage from update_fulfill_htlc or from
  an on-chain claim, which also completes a FAILED outgoing record.
- **Swap ledger** (`ledger.ts`): a `DurableLedger` of `ISwapRecord` rows with
  the reverse and submarine lifecycles as compare-and-swap arrows, a
  write-once preimage no transition removes, and no private key stored
  (`keys.ts` re-derives per-swap keys from the node key and the swap id).
- **Chain resolver** (`chain-resolver.ts`): `observe` reports the funding
  output's status, every spend classified as claim (with the extracted
  preimage), refund or unknown, confirmations against the operator's policy,
  and demotions of recorded facts. Every transaction is fetched by txid and
  checked to hash to it. `verifiedThisSession` is false until the first
  observation after a restart; recorded depths are not trusted before then.
- **Exposure policy** (`exposure.ts`): minimum and maximum swap size, total
  principal at risk, concurrency, fee-rate ceiling and an optional fee
  reserve check when a balance is supplied.

`INodeConfig.swaps.enabled` builds and rehydrates the ledger at construction;
`swapChain()` and `getSwapKeyDeriver()` are the node's seams for an engine.

## Reverse swap provider

`ReverseSwapProvider` (`reverse-engine.ts`) serves the Lightning-to-on-chain
direction. A node runs it with `INodeConfig.swaps.enabled` (daemon:
`BEIGNET_SWAPS=true`); the engine takes a deps object of closures into the
node and never touches chain or Lightning code of its own.

Wire protocol (custom message 44069, subtypes 48 to 53, TLV in `messages.ts`;
even types required, odd optional):

| Message | Carries |
|---|---|
| `SWAP_QUOTE_REQUEST` / `SWAP_QUOTE` | direction, amount; fee terms, limits, refund delta, confirmations, the fee on this amount and the invoice amount. Stateless. |
| `SWAP_CREATE` / `SWAP_CREATE_ACK` | the client's payment hash, claim key, on-chain amount and fee ceiling; the swap id, hold invoice, refund key and height, contract script and address, and every amount. A refusal carries a typed reason. |
| `SWAP_STATUS_REQUEST` / `SWAP_STATUS` | the provider's view of one swap, answered only to the peer that created it: state, funding outpoint and depth, the raw funding transaction, the winning resolution. |
| `SWAP_SUBMARINE_CREATE` (54) / `SWAP_SUBMARINE_CREATE_ACK` (55) | the submarine direction (issue #743): the client's payment hash, refund key, its own invoice for the on-chain amount minus the fee, the on-chain amount and fee ceiling; the swap id, the provider's claim key, refund height, contract script and address, every amount, the depth the funding must reach before the provider pays, the deadline for funding and, informationally, the absolute expiry ceiling the provider's payment is bound by. Quote and status carry `direction`; `SwapWireState` gained the submarine states 12 to 19. |

The client receives exactly `onchainAmountSat`; the invoice is that plus
`totalFeeSat` (flat + ppm + the quoted funding miner fee). The swap id is
derived from the peer and the hash, so an identical repeated create returns
the same ack and any other reuse of a hash is refused. `verifyReverseSwapTerms`
(`client.ts`) is the pure check a client runs before paying: it rebuilds the
contract from its own hash and claim key plus the ack's refund key and height
and requires the ack's script, address, invoice and amounts to agree.

Lifecycle, every arrow a compare-and-swap on the ledger row, persisted BEFORE
the action it licenses:

```text
CREATED  record inserted, then the hold invoice minted with a final CLTV of
         refundDelta + resolution margin + the sweeper's margin + 8
HELD     the COMPLETE committed set admitted through validateReverseSwapAdmission,
         the sweeper's cancel height checked against the refund height, exposure
         re-checked; a partial MPP set never funds
FUNDING  attempt counted, then the funding transaction built by the wallet,
         verified to pay the contract exactly, then its bytes recorded; a row
         with bytes never builds a second transaction
FUNDING_BROADCAST inputs pledged, bytes broadcast (retried per block on failure)
FUNDED   funding confirmed to fundingConfirmations
CLAIMED  a claim spend with a verified preimage at ANY depth, mempool included;
         the preimage is recorded, only then settleHeldHtlc
SETTLED  the hold released
REFUND_PENDING at refundHeight + 1 with no claim: refund built to the node's
         sweep destination, recorded, broadcast; rebuilt at a higher fee every
         refundBumpIntervalBlocks while unconfirmed, never above the rate cap
REFUNDED refund confirmed to resolutionConfirmations; ONLY NOW the hold is
         cancelled
EXPOSED  the node's own sweeper cancelled the hold while coins were, or may
         be, on chain (signed funding bytes whose broadcast threw count, since
         a dropped connection can follow a relay): watching continues, the
         refund still recovers the coins, a late claim still records its
         preimage, swap:exposed is emitted at error level
CANCELLED / FAILED before any funds moved (FAILED from FUNDING only while no
         bytes were ever signed)
```

Rules the engine never breaks: a hold is never cancelled because the refund
height passed or a refund was broadcast; a claim beats a pending refund; a
preimage from any source is retained (a spend of the funding outpoint whose
witness carries a 32-byte element hashing to the payment hash is a claim
even when its signature or MINIMALIF byte is non-canonical: a mined spend
is valid by definition); the funding transaction is never fee-bumped; a
funding broadcast that throws is judged by the chain, not by the error, since
the bytes may have relayed before the connection dropped or be refused as
already mined; a create is refused for any hash the node already holds a
record for (an invoice, a payment it is sending, a parked hold), because
minting a hold invoice on it would overwrite that record; no swap is quoted
while the sweep destination is not native segwit, the only kind the refund
builder pays. On the node side a parked set that already covers the invoice
takes no further part (a late short-expiry part would drag the whole set
into the sweeper's margin), and the per-block sweep waits, bounded, for the
provider's chain look so a claim seen at the block settles before the sweep
judges its hash.

Before the funding bytes leave for the first time the hold is judged again,
live (`heldSnapshot` complete and ACCEPTED, the admission margins at the
current height): the wallet signs asynchronously and a cancel can land
meanwhile, and a restart re-enters at a later height. The row records
`fundingBroadcastAttemptedAt` before the first attempt; a hold cancel on a
FUNDING row without it fails the swap and releases the inputs (nothing
left), with it exposes the row (a broadcast that threw may have relayed).
Exposure accounting counts an EXPOSED row until its resolution, verified
in this process, reached `resolutionConfirmations`; a resolution read back
from storage is history until observed again, and one the chain no longer
shows is demoted to zero depth. A restart redoes the owed action of every unresolved row exactly
once (`startSwapProvider`).

Residual risks an operator accepts: a reorg deeper than
`resolutionConfirmations` after REFUNDED; a funding transaction stuck under
fee with no replacement; a chain stall long enough that the sweeper's cancel
height arrives before the refund resolves (bounded by the admission margins,
never eliminated); no fee estimate fails quotes closed rather than guessing.

Daemon: `GET /swaps/status`, `GET /swaps`, `POST /swaps/cancel` (CREATED or
HELD only); env `BEIGNET_SWAPS`, `BEIGNET_SWAP_FLAT_FEE_SAT`,
`BEIGNET_SWAP_FEE_PPM`, `BEIGNET_SWAP_MIN_SAT`, `BEIGNET_SWAP_MAX_SAT`,
`BEIGNET_SWAP_MAX_EXPOSURE_SAT`, `BEIGNET_SWAP_MAX_CONCURRENT`,
`BEIGNET_SWAP_REFUND_DELTA_BLOCKS`, `BEIGNET_SWAP_FUNDING_CONFS`,
`BEIGNET_SWAP_RESOLUTION_CONFS`; events `swap:created`, `swap:held`,
`swap:funding`, `swap:funded`, `swap:claimed`, `swap:settled`,
`swap:refund-broadcast`, `swap:refunded`, `swap:hold-cancelled`,
`swap:exposed`, `swap:failed`.

## Submarine swap provider (on-chain to Lightning, issue #743)

`SubmarineSwapProvider` (`submarine-engine.ts`) serves the other direction:
the client locks coins in a contract whose preimage branch is this node's,
this node pays the client's own invoice under an absolute expiry ceiling, and
the preimage that payment reveals claims the coins. It runs beside the
reverse engine on the same peer seam and the same ledger when
`INodeConfig.swaps.submarine.enabled` is set (daemon:
`BEIGNET_SWAP_SUBMARINE=true`, which needs `BEIGNET_SWAPS=true`); the fee
terms, exposure caps and confirmation policy are shared, the margins are the
direction's own. The reverse engine stops answering direction 2 quotes and
submarine rows the moment the submarine engine exists, so one request gets
one answer.

Wire: a quote (48/49) with `direction` 2, `SWAP_SUBMARINE_CREATE` (54) and
`SWAP_SUBMARINE_CREATE_ACK` (55), status (52/53) with the submarine states.
The client mints its invoice for `onchainAmountSat - fee` BEFORE the create,
so the provider derives the fee from the invoice (a whole number of sats)
and accepts it when it covers `submarineSwapFee` at the current claim fee
rate and stays under the client's `maxTotalFeeSat`; the ack echoes what was
accepted. `verifySubmarineSwapTerms` (`client.ts`) is the client's pure check:
the contract rebuilt from its refund key and the provider's claim key must
match the ack's script and address, its invoice must carry the hash, network
and acked amount, and the fee and refund window must be within policy.

Admission, at create and again at dispatch: the invoice decodes for this
network with the request's hash, an amount and a payment secret; it is not
payable to this node (payee, a route hint through this node with no channel
to the payee, or a blinded path this node introduces: the local-origin
payment path does not enter the JIT interception, so that composition is
refused as `SELF_PAYMENT`); it stays valid for `minInvoiceExpirySeconds`;
the hash is new to the node; outbound capacity covers the invoice; the
exposure caps admit the amount. The ceiling is `C = refundHeight -
claimSafetyBlocks - resolutionSafetyBlocks` and the fit is `height +
fundingConfirmations + routeCltvBudgetBlocks + min_final_cltv_expiry + 3 <=
C` (`CLTV_UNFITTABLE` otherwise, FAILED when it stops holding before the
payment goes out); `validateSubmarineSwapAdmission` is run on the same
numbers.

Lifecycle, every arrow a compare-and-swap on the ledger row, persisted BEFORE
the action it licenses:

```text
CREATED       terms verified, row inserted with the invoice and the ceiling
FUNDING_SEEN  an output paying the contract, of at least the amount, seen at
              any depth (underpaid outputs are logged and ignored, overpayment
              is swept by the claim); re-pointed while unconfirmed if a
              replacement appears, FUNDING_LOST when none is left
FUNDED        confirmed to fundingConfirmations and unspent
PAYING        the row moved, with the ceiling, the fee cap and the attempt
              count, THEN sendPaymentWithOptions(maxCltvExpiryHeight: C);
              the observation is the last await before the CAS, so a cancel
              or a spend landing meanwhile fails the CAS instead of racing it
PAYMENT_UNRESOLVED  HTLCs out past unresolvedAfterBlocks; informational
PREIMAGE_KNOWN the node's HTLC view carries the preimage (a fulfil, or a claim
              seen on chain downstream), recorded write-once
CLAIM_BROADCAST claim built to the sweep destination, its bytes and the attempt
              marker persisted, then broadcast; rebuilt at a higher fee every
              claimBumpIntervalBlocks while unconfirmed (BIP 125 floor against
              our own previous claim, and against a client refund seen in the
              mempool), capped at maxFeeRateSatPerVbyte until the deadline
              window, where the whole output above dust may go to fees
CLAIM_CONFIRMED the claim at resolutionConfirmations
PAYMENT_FAILED every HTLC terminal without a preimage (the node's view, never
              a wall clock, a FAILED record or a thrown call); a preimage
              learned later still promotes the row and the claim is pursued
EXPOSED       a payment is out while the contract is not claimable: the funding
              vanished, or a foreign spend confirmed; the payment keeps being
              read (a failure with nothing paid ends in PAYMENT_FAILED, a
              returned funding is claimed) and a confirmed refund with the
              preimage known is logged as a realised loss and stops counting
              as exposure once verified at policy depth
CANCELLED / FAILED before anything was paid: the invoice expired, the ceiling
              stopped fitting, the client spent the funding, or the operator
              cancelled (allowed until PAYING)
```

What the payment call proves: after `sendPaymentWithOptions` returns or
throws, the engine reads `getOutgoingHtlcs`. A preimage promotes the row;
no record and no HTLC means the dispatch left nothing behind and the attempt
is final; a resolved view without a preimage is a failed payment; anything
else is a payment in flight, whatever the record's status. On restart a
PAYING row whose node holds no record and no HTLC is dispatched again after
the same checks, bounded by `maxPaymentDispatchAttempts`; a row with a record
is left to the view.

Status answers name the claim only once a broadcast was attempted, and
only to the peer that created the swap; the reverse engine answers unknown
ids and its own rows, the submarine engine its own.

Residual risks an operator accepts: a fee spike inside the deadline window
that the whole output cannot outbid; a reorg deeper than
`resolutionConfirmations` after CLAIM_CONFIRMED; a client that holds the
payment until the ceiling, settles, and refunds at once leaves exactly
`claimSafetyBlocks + resolutionSafetyBlocks` blocks for the claim; a hash
the node already holds (a failed earlier payment among them) cannot be swapped
again, the client needs a new invoice.

Daemon: `GET /swaps/status` reports the direction under `submarine`,
`GET /swaps` rows carry `direction`, `POST /swaps/cancel` cancels a submarine
row before PAYING; env `BEIGNET_SWAP_SUBMARINE`,
`BEIGNET_SWAP_CLAIM_SAFETY_BLOCKS`, `BEIGNET_SWAP_PAYMENT_MAX_FEE_PPM`,
`BEIGNET_SWAP_CLAIM_BUMP_INTERVAL_BLOCKS`,
`BEIGNET_SWAP_SUBMARINE_REFUND_DELTA_BLOCKS`; events `swap:created`,
`swap:funding-seen`, `swap:funded`, `swap:funding-lost`, `swap:paying`,
`swap:payment-unresolved`, `swap:preimage`, `swap:claim-broadcast`,
`swap:claim-confirmed`, `swap:payment-failed`, `swap:exposed`,
`swap:cancelled`, `swap:failed`, every payload carrying `direction`.

Tests: `tests/lightning/swap-submarine-engine.test.ts` (the engine over
fakes, including the restart matrix and the shared peer seam),
`tests/lightning/swap-submarine-node.test.ts` (two real nodes, the real
payment engine under the real ceiling, hold invoices for the parked and
failed cases), and the regtest suites
`tests/lightning/interop/swap-submarine-{lnd,cln}.test.ts`
(`REQUIRE_SWAP_REGTEST=1`).

## Remaining work

Issue 737 remains open for:

- Same-node JIT composition: paying the provider's own JIT client's invoice
  does not invoke the forwarded HTLC interception path, so a submarine
  create whose invoice routes through this node with no channel to the
  payee is refused rather than served.
- Design Taproot separately. A key-path witness does not reveal the preimage;
  cooperative claims require a preimage exchange and signing protocol with nonce
  handling and recovery. This P2WSH implementation does not implement that
  protocol or claim compatibility with an existing swap service.

## Verification

`tests/lightning/swaps.test.ts` covers invalid keys, lengths, hashes, amounts,
fees, heights, witness mutations, exact MPP accounting and timeout boundaries.
`tests/lightning/fixtures/swaps/p2wsh.json` pins test-only keys, synthetic funding,
script/address, signatures and signed transactions. BIP143 digest serialization
is cross-checked independently of bitcoinjs transaction hashing in the test.
The fixture is a reproducible regression vector, not a live funding transaction.

`tests/lightning/interop/swap-p2wsh-mempool.test.ts` uses Bitcoin Core regtest to
verify real funded spends with `testmempoolaccept`, the exact refund finality
boundary, claim validity after expiry, confirmed refund consumption, invalid
signatures and CLTV bypass attempts, and hash-matching 31/33-byte secrets that
must still fail Script execution. It also accepts and extracts claims with all
six defined ECDSA sighash combinations. It skips if Core is absent unless
`REQUIRE_SWAP_REGTEST=1` is set, which makes missing infrastructure fail the run.

```sh
npx mocha --exit --timeout 20000 -r ts-node/register tests/lightning/swaps.test.ts
REQUIRE_SWAP_REGTEST=1 npx mocha --exit --timeout 120000 -r ts-node/register tests/lightning/interop/swap-p2wsh-mempool.test.ts
```
