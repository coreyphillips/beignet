/**
 * Dual-funding contribution selection: which IFundingProvider method funds a
 * v2 open, and what to do when the configured provider predates it.
 *
 * Three sites fund a dual-funding contribution from the on-chain wallet: the
 * opener's auto-funding, a lease seller's acceptor contribution and an RBF
 * contribution raise. All three route through here so the method preference
 * and the fallback live in one place rather than being re-spelled (and drifting
 * apart) at each site.
 *
 * Type-only imports by design: channel/channel-manager consumes this module at
 * runtime while node/types references channel/channel-manager, so keeping this
 * a leaf with no runtime imports keeps that edge free of a cycle. (bitcoinjs
 * below is an external package, not part of that edge.)
 */

import * as bitcoin from 'bitcoinjs-lib';
import type { IFundingProvider, IUtxoSelectionOpts } from './types';
import type { ISpliceWalletInput } from '../channel/channel';

/** What a contribution selection hands back: our inputs plus a change script. */
export interface IDualFundingSelection {
	inputs: ISpliceWalletInput[];
	changeScript: Buffer;
}

/**
 * Whether this provider can source a fixed-amount dual-funding contribution at
 * all. False leaves the legacy caller-driven flow in place: the embedder adds
 * its own inputs via addTxInput.
 */
export function canSelectDualFundingInputs(
	fp?: IFundingProvider | null
): fp is IFundingProvider {
	return Boolean(fp?.selectDualFundingInputs ?? fp?.selectSpliceInputs);
}

/**
 * Source a dual-funding contribution, preferring the dual-funding-aware
 * selector.
 *
 * selectSpliceInputs is the fallback for providers written before
 * selectDualFundingInputs existed. It sizes with the splice weight, which
 * carries a shared 2-of-2 funding input a v2 open funding transaction does not
 * have, so it can under-reserve on a fragmented wallet (issue #380). Nothing
 * here can correct a third-party provider's arithmetic; the fallback keeps such
 * embedders working exactly as they did rather than breaking them outright, and
 * WalletFundingProvider implements the correct method.
 *
 * `topUp` marks an amount that already covers the contribution's fixed fee
 * terms because the contribution already holds registered inputs (an RBF
 * raise), so the selection owes only the marginal per-input weight of the coins
 * it adds. The splice fallback cannot express that distinction and simply
 * over-reserves, as it always has.
 */
export function selectDualFundingContribution(
	fp: IFundingProvider,
	amountSats: bigint,
	feeratePerKw: number,
	initiator: boolean,
	topUp = false,
	opts?: IUtxoSelectionOpts
): Promise<IDualFundingSelection> {
	// An empty directed list is a caller error, not "no direction": passing
	// it through would combine with the providers' unrestricted-selection
	// fallback and fund with arbitrary coins while the caller believed the
	// selection was constrained (issue #572 review). The throw lands in the
	// auto-funding rejection arm, failing the open loudly.
	if (opts?.utxos && opts.utxos.length === 0) {
		throw new Error(
			'fundingUtxos.utxos must not be empty (an empty directed list would select unrestricted coins)'
		);
	}
	if (fp.selectDualFundingInputs) {
		return fp.selectDualFundingInputs(
			amountSats,
			feeratePerKw,
			initiator,
			topUp,
			opts
		);
	}
	if (fp.selectSpliceInputs) {
		return fp.selectSpliceInputs(amountSats, feeratePerKw, opts);
	}
	throw new Error(
		'funding provider cannot select wallet inputs (needs selectDualFundingInputs or selectSpliceInputs)'
	);
}

/**
 * Verify that a selection honored a directed IUtxoSelectionOpts. The opts are
 * a trailing OPTIONAL parameter, so a third-party provider written against
 * the older signature silently ignores them and still returns a successful
 * selection over arbitrary coins; the caller's promise ("these outpoints fund
 * this open") must therefore be checked against what actually came back
 * before anything is registered (issue #572 review).
 *
 * Returns null when the selection complies: every named outpoint is among the
 * returned inputs, and without allowTopUp nothing else is. Txid comparison is
 * case-normalized (the public API accepts uppercase hex). A non-null return
 * names the first violation and the selection must be treated as a funding
 * failure, releasing its pledges.
 */
export function verifyDirectedSelection(
	inputs: ISpliceWalletInput[],
	directed: NonNullable<IUtxoSelectionOpts>
): string | null {
	if (!directed.utxos) return null;
	// Defense in depth behind selectDualFundingContribution's throw: an
	// empty directed list must read as a violation, never as compliance,
	// or it silently authorizes whatever the fallback selection picked.
	if (directed.utxos.length === 0) {
		return 'fundingUtxos.utxos is empty (an empty directed list cannot authorize a selection)';
	}
	const selected = new Set<string>();
	for (const input of inputs) {
		try {
			selected.add(
				`${bitcoin.Transaction.fromBuffer(input.prevTx).getId()}:${
					input.prevOutputIndex
				}`
			);
		} catch {
			return 'directed selection returned an unreadable prevTx';
		}
	}
	const named = new Set(
		directed.utxos.map((u) => `${u.txid.toLowerCase()}:${u.vout}`)
	);
	for (const key of named) {
		if (!selected.has(key)) {
			return `provider ignored fundingUtxos (missing requested outpoint ${key})`;
		}
	}
	if (!directed.allowTopUp) {
		for (const key of selected) {
			if (!named.has(key)) {
				return `provider ignored fundingUtxos (unrequested input ${key} without allowTopUp)`;
			}
		}
	}
	return null;
}
