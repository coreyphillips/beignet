import { Transaction } from 'bitcoinjs-lib';
import type { AssetSpliceConstructionEvent } from '../channel/asset-splice-construction';
import type { IFinalSpliceTerms } from '../channel/final-splice-candidate';
import {
	assembleFinalSplice,
	verifyFinalSpliceContribution
} from '../channel/final-splice-funding';
import { spliceConstruction } from '../channel/final-splice-transcript';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import { MessageType as M } from '../message/types';
import {
	loadAssetSpliceExitProofs,
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent
} from './asset-splice-exit-proofs';
import { assetSpliceAttemptId } from './asset-splice-wallet-inputs';
import type { SqliteStorage } from './sqlite-storage';

interface Frame {
	kind: 'asset-splice-signature';
	digest: string;
	local: boolean;
	type: M;
	payload: string;
}

export function assetSpliceSignatureFrame(
	store: SqliteStorage,
	id: string,
	digest: string,
	local: boolean,
	type: M,
	payload?: Buffer
): Buffer | undefined {
	const head = store.readAssetSpliceJournal<Frame>(id);
	const matches = head.records.filter(
		(r) =>
			r.kind === 'asset-splice-signature' &&
			r.digest === digest &&
			r.local === local &&
			r.type === type
	);
	if (matches.length > 1)
		throw new Error('Ambiguous recorded asset splice signature');
	const old = matches[0];
	if (old) {
		const raw = Buffer.from(old.payload, 'hex');
		if (
			raw.toString('hex') !== old.payload ||
			(payload && !raw.equals(payload))
		)
			throw new Error('Conflicting asset splice signature replay');
		return raw;
	}
	if (payload)
		store.appendAssetSpliceEvent(id, head, {
			kind: 'asset-splice-signature',
			digest,
			local,
			type,
			payload: payload.toString('hex')
		} satisfies Frame);
	return;
}

/** Rebuild the released funding exchange from the device journal even if the candidate has already spent the parent. */
export function releasedAssetSplice(
	store: SqliteStorage,
	id: string,
	attempt: string
) {
	assetSpliceAttemptId(attempt);
	if (!store.canSpliceDualFundedAssets)
		throw new Error(
			'Released funding replay requires the enrolled original device'
		);
	const history = store.readAssetSpliceJournal<
		AssetSpliceConstructionEvent | AssetSpliceExitEvent
	>(id).records;
	const starts = history.filter(
		(
			e
		): e is Extract<
			AssetSpliceConstructionEvent,
			{ kind: 'construction-start' }
		> => e.kind === 'construction-start' && e.attempt === attempt
	);
	if (starts.length > 1)
		throw new Error('Ambiguous asset splice construction attempt');
	const start = starts[0];
	if (!start) return;
	const { finalDigest, initiator } = start;
	const phases = history.filter(
		(e): e is AssetSpliceExitEvent =>
			e.kind === 'exit-proofs' ||
			e.kind === 'funding-reserved' ||
			e.kind === 'funding-released'
	);
	const packets = phases.filter(
		(e): e is Extract<AssetSpliceExitEvent, { kind: 'funding-released' }> =>
			e.kind === 'funding-released' && e.finalDigest === finalDigest
	);
	if (!packets.length) return;
	if (
		packets.length !== 1 ||
		!publishableAssetSpliceEvidence(phases, id).some(
			(e) => e.finalDigest === finalDigest
		)
	)
		throw new Error('Invalid original asset splice release');
	const receipt = loadAssetSpliceExitProofs(store, id, finalDigest),
		parent = receipt.parent,
		candidate = receipt.candidate;
	if (
		start.txid !== candidate.fundingTxid ||
		!assetSpliceSignatureFrame(
			store,
			id,
			finalDigest,
			true,
			M.COMMITMENT_SIGNED
		) ||
		!assetSpliceSignatureFrame(
			store,
			id,
			finalDigest,
			false,
			M.COMMITMENT_SIGNED
		)
	)
		throw new Error('Released funding lacks its original commitment exchange');
	const buyer = candidate.localRecovery,
		old = parent.localRecovery;
	const deltas = [
		BigInt(buyer.localBalanceMsat) - BigInt(old.localBalanceMsat),
		BigInt(buyer.remoteBalanceMsat) - BigInt(old.remoteBalanceMsat)
	];
	if (deltas.some((v) => v % 1000n !== 0n))
		throw new Error('Splice balance changes must be whole satoshis');
	const tx = Transaction.fromHex(candidate.funding.fundingTxHex);
	const key = (
		b: typeof parent,
		side: 'localFundingPubkey' | 'remoteFundingPubkey'
	) => Buffer.from(b.funding[side], 'hex');
	const terms: IFinalSpliceTerms = {
		parent: Transaction.fromHex(parent.funding.fundingTxHex),
		parentIndex: parent.outputIndex,
		oldLocalKey: key(parent, 'localFundingPubkey'),
		oldPeerKey: key(parent, 'remoteFundingPubkey'),
		newLocalKey: key(candidate, 'localFundingPubkey'),
		newPeerKey: key(candidate, 'remoteFundingPubkey'),
		localIsSpliceInitiator: initiator,
		localDelta: deltas[0] / 1000n,
		peerDelta: deltas[1] / 1000n,
		localFeeBudget: BigInt(start.terms.localFeeBudget),
		feerate: start.terms.feerate,
		dust: BigInt(start.terms.dust),
		locktime: tx.locktime,
		assetFundingRoots: {
			parent: Buffer.from(parent.fundingRoot, 'hex'),
			candidate: Buffer.from(candidate.fundingRoot, 'hex')
		}
	};
	const frames = history
		.filter(
			(
				e
			): e is Extract<
				AssetSpliceConstructionEvent,
				{ kind: 'construction-frame' }
			> => e.kind === 'construction-frame' && e.attempt === attempt
		)
		.map((e) => {
			const raw = Buffer.from(e.payload, 'hex');
			if (
				e.finalDigest !== finalDigest ||
				e.initiator !== initiator ||
				e.txid !== candidate.fundingTxid ||
				raw.toString('hex') !== e.payload ||
				raw.subarray(0, 32).toString('hex') !== id ||
				![M.TX_ADD_INPUT, M.TX_ADD_OUTPUT, M.TX_COMPLETE].includes(e.type)
			)
				throw new Error(
					'Funding construction differs from its retained splice'
				);
			return {
				kind: 'wire' as const,
				local: e.local,
				type: e.type,
				payload: e.payload
			};
		});
	const g = spliceConstruction(
			{ intent: { initiator }, messages: frames },
			terms
		),
		c = g.build();
	if (
		c.tx.toHex() !== tx.toHex() ||
		c.fundingIndex !== candidate.outputIndex ||
		!g.localComplete ||
		!g.peerComplete ||
		g.localComplete.toString('hex') !== start.localComplete
	)
		throw new Error(
			'Released asset splice does not match its original construction'
		);
	const nonce = (raw: Buffer) =>
		decodeTxCompleteMessage(raw, { taproot: true }).fundingInputNonce!;
	const channel = Buffer.from(id, 'hex'),
		ours = nonce(g.localComplete),
		peer = nonce(g.peerComplete),
		wire = Buffer.from(packets[0].wire, 'hex');
	verifyFinalSpliceContribution(c, terms, channel, wire, true, ours, peer);
	return {
		get wire() {
			return Buffer.from(wire);
		},
		receive(raw: Buffer) {
			verifyFinalSpliceContribution(c, terms, channel, raw, false, ours, peer);
			assetSpliceSignatureFrame(
				store,
				id,
				finalDigest,
				false,
				M.TX_SIGNATURES,
				raw
			);
		},
		transaction() {
			const other = assetSpliceSignatureFrame(
				store,
				id,
				finalDigest,
				false,
				M.TX_SIGNATURES
			);
			return other
				? Transaction.fromBuffer(
						assembleFinalSplice(
							c,
							terms,
							channel,
							ours,
							peer,
							wire,
							other
						).toBuffer()
				  )
				: undefined;
		}
	};
}
