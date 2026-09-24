# Channel state-machine leniencies: acceptor affordability counts trimmed HTLCs, reestablish gaps larger than one are tolerated, settles for uncommitted HTLCs are accepted, and upfront_shutdown_script is advertised but never enforced

Labels: bug

Found during a security audit of the channel state machine. Low-severity spec-conformance items; none loses our funds, but each lets a desynced or misbehaving session continue where a conforming node would fail cleanly, or (the first) fails an honest peer.

## 1. Acceptor-side affordability counts trimmed HTLCs

`handleUpdateAddHtlc` (`src/lightning/channel/channel.ts:3431-3438`) and `handleUpdateFee` (`:5419-5432`) price the funder's required fee with `funderCommitmentCostSats(..., this._countActiveHtlcs() + 1, ...)`, and `_countActiveHtlcs` (`:14796`) counts every PENDING or COMMITTED entry, trimmed ones included. BOLT 3 charges 172 WU only for untrimmed outputs, and LND, Eclair and CLN compute their send-side affordability that way. A funder holding k dust HTLCs that offers an HTLC or an `update_fee` it can afford by the spec formula but not by ours (a `172 * k * feerate / 1000` sat difference) is wire-failed by both arms, i.e. we force-close an honest peer at the boundary.

Fix: count the HTLCs that survive `filterUntrimmedHtlcs` at the relevant dust limit and feerate.

## 2. Reestablish tolerates counters more than one behind

`channel.ts:10490-10520` retransmits the latest `commitment_signed` whenever `msg.nextCommitmentNumber <= remoteCommitmentNumber`, even when the peer is two or more behind, where BOLT 2 says the node SHOULD send an error and fail the channel. The revocation side handles only `nextRevocationNumber + 1n === localCommitmentNumber` (`:10389`); a peer two or more revocations behind is not failed and the exchange continues until a later signature mismatch.

Fix: fail the channel on a gap larger than one in either counter.

## 3. Settles accepted for HTLCs never committed

`handleUpdateFulfillHtlc` / `handleUpdateFailHtlc` (`:3725`, `:4030`) accept a settle for an OFFERED entry still PENDING (never in any commitment), where BOLT 2 says MUST fail the channel. A premature fulfil carries a valid preimage, so no loss, but the state is off-spec.

Fix: require `state === COMMITTED` (or `addRemoteCommitted !== false`) before accepting a peer settle.

## 4. `option_upfront_shutdown_script` advertised but not enforced

`implementedFeatures()` claims the feature (`src/lightning/features/flags.ts:352`), but `handleShutdown` (`channel.ts:7076`) never compares the script with the `upfront_shutdown_script` the peer sent in `open_channel` / `accept_channel`. A peer that REQUIRES the feature is not disconnected, and the guarantee it believes it has is silently not enforced.

Fix: store the peer's upfront script and enforce equality in `handleShutdown`, or stop advertising the bit.
