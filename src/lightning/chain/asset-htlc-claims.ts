import {
	confirmAssetPayout,
	detached,
	retainAssetPayout
} from './asset-payout-receipt';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetOpeningHtlcPayout,
	IAuxiliaryDualFunding
} from '../channel/asset-opening-provider';
import type { IFinalOpeningRuntime } from '../channel/final-opening-runtime';
import { decodeAssetUpdateIntent } from '../channel/asset-splice-update-intent';
import type { IAssetSpliceLeaves } from '../channel/final-opening-commitment';
import { sha256 } from '../crypto/provider';
import { derivePrivateKey, deriveRevocationPrivkey } from '../keys/derivation';
import { getPerCommitmentPoint } from '../channel/channel-helpers';
import { deriveChannelKeys } from '../keys/wallet-keys';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import { MessageType } from '../message/types';
import {
	buildTaprootSecondLevelOutput,
	tweakTaprootKeyPathPrivkey
} from '../script/commitment-taproot';
import { verifyTaprootHtlcLeaf } from '../script/htlc-taproot';
import {
	assetUpdateHistory,
	inFlightAssetUpdates
} from '../storage/asset-update-history';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent
} from '../storage/asset-splice-exit-proofs';
import { assetSpliceSignatureFrame } from '../storage/asset-splice-release-replay';
import { assetHtlcSweepSigner, checkSponsoredHtlc } from './asset-htlc-bitcoin';
import { assetHtlcVirtualSigner } from './asset-htlc-signing';
import {
	type matchedAssetPayoutViews,
	retainedAssetFundingLineage
} from './asset-splice-output-view';
import { finalHtlcClaim, type IFinalOutputClaim } from './final-output-claims';

type Match = ReturnType<typeof matchedAssetPayoutViews>[number];

type Purpose = IAssetOpeningHtlcPayout['kind'];

export function assetHtlcClaims(
	runtime: IFinalOpeningRuntime,
	id: string,
	parent: Transaction,
	destination: Buffer,
	rate: number,
	match: Match,
	provider?: IAuxiliaryDualFunding,
	trimmed?: (hash: Buffer, htlcId: bigint, preimage?: Buffer) => void
): IFinalOutputClaim[] {
	const { storage } = runtime,
		{ view, point, state, holder } = match;
	if (
		!storage.canRecoverAssetSplice ||
		(!view.htlcs.length && (!trimmed || state === 0n))
	)
		return [];
	const opening = storage.loadFinalDaemonOpening(id)!;
	const history = assetUpdateHistory(storage, id),
		secured = history.states.get(state),
		// A peer commitment we signed in an unsecured round names the same obligations.
		ledger =
			secured ??
			(holder === 'remote'
				? inFlightAssetUpdates(history).get(state)
				: undefined);
	if (!ledger) throw Error('Missing signed asset HTLC state');
	const disclosures = [...history.stages]
		.filter(([stage]) => stage.endsWith('/intent'))
		.flatMap(([, bytes]) =>
			decodeAssetUpdateIntent(
				id,
				opening.candidate.isInitiator,
				Buffer.from(bytes, 'hex')
			)
		)
		.flatMap((change) => (change.kind === 'fulfill' ? [change.preimage] : []));
	const preimageFor = (hash: Buffer): Buffer | undefined =>
		[...disclosures, storage.loadPreimage(hash.toString('hex'))].find(
			(p): p is Buffer => !!p && p.length === 32 && sha256(p).equals(hash)
		);
	if (trimmed) {
		const offeredOutputs = new Set(
			view.htlcs
				.filter((h) => h.htlc.offeredBy === 'local')
				.map((h) => String(h.htlc.id))
		);
		for (const h of ledger.htlcs) {
			if (h.offeredBy !== 'local' || offeredOutputs.has(h.id)) continue;
			if (h.allocations.length)
				throw Error('Signed asset HTLC missing its commitment output');
			const hash = Buffer.from(h.paymentHash, 'hex');
			trimmed(hash, BigInt(h.id), preimageFor(hash));
		}
	}
	if (!view.htlcs.length) return [];
	const keys = deriveChannelKeys(
		runtime.root,
		1,
		opening.session.channelKeyIndex
	);
	const local = holder === 'local';
	if (
		local &&
		!getPerCommitmentPoint(keys.perCommitmentSeed, state).equals(point)
	)
		throw Error('Local HTLC commitment point differs from this device');
	const htlcKey = derivePrivateKey(
			keys.htlcBasepointSecret,
			point,
			keys.channelBasepoints.htlcBasepoint
		),
		delayedKey = derivePrivateKey(
			keys.delayedPaymentBasepointSecret,
			point,
			keys.channelBasepoints.delayedPaymentBasepoint
		);
	const revoked =
		match.revoked &&
		deriveRevocationPrivkey(
			keys.revocationBasepointSecret,
			match.revoked,
			keys.channelBasepoints.revocationBasepoint,
			point
		);
	let signed: ReturnType<typeof decodeCommitmentSignedMessage> | undefined;
	if (local) {
		if (!secured) throw Error('Missing signed asset HTLC state');
		const memberIndex = secured.members.findIndex(
			(b) => Transaction.fromHex(b.localCommitment).getId() === parent.getId()
		);
		let raw =
			memberIndex < 0
				? undefined
				: Buffer.from(secured.peerCommitments[memberIndex], 'hex');
		if (!raw) {
			const receipt = publishableAssetSpliceEvidence(
				storage.readAssetSpliceJournal<AssetSpliceExitEvent>(id).records,
				id
			).find(
				(r) =>
					r.stateNumber === String(state) &&
					Transaction.fromHex(r.candidate.localCommitment).getId() ===
						parent.getId()
			);
			if (receipt)
				raw = assetSpliceSignatureFrame(
					storage,
					id,
					receipt.finalDigest,
					false,
					MessageType.COMMITMENT_SIGNED
				);
		}
		if (!raw)
			throw Error('Missing peer signatures for this observed HTLC commitment');
		signed = decodeCommitmentSignedMessage(raw, { customRecords: true });
		if (
			signed.channelId.toString('hex') !== id ||
			!signed.fundingTxid?.equals(parent.ins[0].hash) ||
			signed.htlcSignatures.length !== view.htlcs.length ||
			view.htlcs.some(
				(h, i) =>
					!verifyTaprootHtlcLeaf(
						h.digest,
						view.keys.remoteHtlcPubkey,
						signed!.htlcSignatures[i]
					)
			)
		)
			throw Error('Peer HTLC signatures differ from the observed commitment');
	}
	return view.htlcs.flatMap((h, i) => {
		const { htlc } = h,
			offered = htlc.offeredBy === 'local';
		const obligation = ledger.htlcs.find(
			(v) => v.id === String(htlc.id) && v.offeredBy === htlc.offeredBy
		);
		if (
			!obligation ||
			obligation.paymentHash !== htlc.paymentHash.toString('hex') ||
			obligation.cltvExpiry !== htlc.cltvExpiry ||
			obligation.amountMsat !== String(htlc.amountMsat)
		)
			throw Error('HTLC differs from the signed obligation');
		const allocations = obligation.allocations.map((a) => ({
			assetId: a.assetId,
			units: BigInt(a.units)
		}));
		const leaves: IAssetSpliceLeaves = match.assets;
		const aux = leaves.htlcs?.find(
			(a) => a.offeredBy === htlc.offeredBy && a.id === htlc.id
		);
		if (!!aux !== !!allocations.length)
			throw Error(
				'HTLC asset recovery leaves differ from the signed allocations'
			);
		const second = buildTaprootSecondLevelOutput(
			view.keys.revocationPubkey,
			view.keys.localDelayedPubkey,
			view.toSelfDelay,
			undefined,
			aux ? { finalLeaf: aux.secondLevel } : 'final'
		);
		const preimage = preimageFor(htlc.paymentHash);
		const claim = finalHtlcClaim({
			h,
			parent,
			local,
			revoked,
			delayedKey,
			htlcKey,
			destination: aux
				? Buffer.concat([Buffer.of(0x51, 32), Buffer.alloc(32)])
				: destination,
			feeRate: rate,
			preimage,
			peerSignature: signed?.htlcSignatures[i],
			second,
			toSelfDelay: view.toSelfDelay
		});
		if (!claim) return [];
		if (!aux) return [claim];
		const kind: Purpose = revoked
			? 'htlc_revocation'
			: local
			? offered
				? 'htlc_second_level_timeout'
				: 'htlc_second_level_success'
			: offered
			? 'htlc_timeout'
			: 'htlc_success';
		const bind = (
			plain: IFinalOutputClaim,
			source: Transaction,
			purpose: Purpose
		): IFinalOutputClaim => {
			const template = plain.tx && detached(plain.tx);
			const wrapped: IFinalOutputClaim = {
				...plain,
				confirmedOnly: true,
				tx: null,
				sponsor: false,
				child: undefined
			};
			if (!plain.sponsor)
				wrapped.confirmAssetPayout = confirmAssetPayout(
					storage,
					provider,
					id,
					source.getId(),
					plain.outputIndex
				);
			if (
				!template ||
				provider?.assetSpliceRecoveryVersion !== 1 ||
				!provider.recoverHtlc
			)
				return wrapped;
			const sponsored = plain.sponsor;
			if (sponsored) {
				wrapped.tx = detached(template);
				wrapped.sponsor = true;
			}
			wrapped.recover = async (feeTx) => {
				const retained = storage.assetOpeningPayout(
					id,
					source.getId(),
					undefined,
					plain.outputIndex
				);
				if (retained) return Transaction.fromBuffer(retained);
				const draft = detached(template);
				if (sponsored) checkSponsoredHtlc(template, feeTx);
				else draft.setWitness(0, []);
				const childSpend = purpose.startsWith('second_level_');
				const secret = revoked
					? tweakTaprootKeyPathPrivkey(
							revoked,
							childSpend ? second.merkleRoot : h.tree.merkleRoot
					  )
					: childSpend
					? delayedKey
					: htlcKey;
				const leaf = revoked
					? undefined
					: childSpend
					? second.delay
					: offered
					? h.tree.timeout
					: h.tree.success;
				const bitcoin = assetHtlcSweepSigner(
					template,
					source.outs[plain.outputIndex],
					secret,
					leaf
				);
				const context = {
					walletGeneration: 5 as const,
					fundingLineage: retainedAssetFundingLineage(
						storage,
						id,
						opening.candidate,
						Buffer.from(parent.ins[0].hash).reverse().toString('hex'),
						parent.ins[0].index
					),
					candidate: JSON.parse(
						JSON.stringify(opening.candidate)
					) as typeof opening.candidate,
					holder,
					virtualPayout: {
						channelId: id,
						fundingTxid: Buffer.from(parent.ins[0].hash)
							.reverse()
							.toString('hex'),
						fundingOutputIndex: parent.ins[0].index,
						stateNumber: String(state),
						revocationPubkey: Buffer.from(view.keys.revocationPubkey)
					},
					fundingProofs: Buffer.from(match.fundingProofs, 'hex'),
					exitProofs: Buffer.from(match.exitProofs, 'hex'),
					commitment: detached(parent),
					parent: detached(source),
					outputIndex: plain.outputIndex,
					commitmentOutputIndex: h.outputIndex,
					kind: purpose,
					htlc: {
						...htlc,
						paymentHash: Buffer.from(htlc.paymentHash),
						allocations: allocations.map((a) => ({ ...a }))
					},
					keys: {
						localDelayedPubkey: Buffer.from(view.keys.localDelayedPubkey),
						remotePaymentPubkey: Buffer.from(view.keys.remotePaymentPubkey),
						revocationPubkey: Buffer.from(view.keys.revocationPubkey),
						localHtlcPubkey: Buffer.from(view.keys.localHtlcPubkey),
						remoteHtlcPubkey: Buffer.from(view.keys.remoteHtlcPubkey)
					},
					toSelfDelay: view.toSelfDelay,
					preimage: preimage
						? Buffer.from(preimage)
						: childSpend
						? source.ins[plain.outputIndex]?.witness.find(
								(w) => w.length === 32 && sha256(w).equals(htlc.paymentHash)
						  )
						: undefined,
					peerHtlcSignatures: signed?.customRecords?.get(65537n),
					childSignatureIndex: i,
					secondLevelTemplate: detached(h.secondLevelTx),
					transaction: detached(sponsored ? feeTx! : draft)
				};
				let active = true;
				const virtual = assetHtlcVirtualSigner(
					context,
					h,
					htlcKey,
					delayedKey,
					revoked
				);
				let payout: Transaction | null;
				try {
					payout = await provider.recoverHtlc!({
						...context,
						signVirtual(spend) {
							if (!active) throw Error('Expired HTLC signing callback');
							return virtual(spend);
						},
						signSweep(tx) {
							if (sponsored || !active)
								throw Error('Invalid HTLC signing stage');
							return bitcoin.sign(tx);
						}
					});
				} finally {
					active = false;
				}
				if (!payout) return null;
				if (
					sponsored
						? !feeTx!.toBuffer().equals(payout.toBuffer())
						: !bitcoin.accepts(payout)
				)
					throw Error('Wallet returned an unauthorized asset HTLC transaction');
				if (!sponsored)
					return retainAssetPayout(
						storage,
						provider,
						id,
						source.getId(),
						plain.outputIndex,
						payout
					);
				return Transaction.fromBuffer(
					storage.assetOpeningPayout(
						id,
						source.getId(),
						payout.toBuffer(),
						plain.outputIndex
					)!
				);
			};
			return wrapped;
		};
		const resolved = bind(claim, parent, kind);
		if (claim.child)
			resolved.child = (spend, index) => {
				const input = spend.ins[index];
				if (
					!input ||
					spend.version !== h.secondLevelTx.version ||
					spend.locktime !== h.secondLevelTx.locktime ||
					!input.hash.equals(parent.getHash()) ||
					input.index !== h.outputIndex ||
					input.sequence !== h.secondLevelTx.ins[0].sequence
				)
					return null;
				const child = claim.child!(spend, index);
				return (
					child &&
					bind(
						child,
						spend,
						revoked ? 'second_level_revocation' : 'second_level_delayed'
					)
				);
			};
		return [resolved];
	});
}
