import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import type { SqliteStorage } from './sqlite-storage';
import type { FinalOpeningAuthority } from './final-opening-authority';
import { assetUpdateHistory } from './asset-update-history';
import {
	checkUpdateNonce,
	spliceCommitmentNonceContext,
	updateVerificationNonce,
	type IFinalUpdateNonce
} from './final-update-signing';
import { deriveChannelKeys } from '../keys/wallet-keys';
import { MAX_INDEX, generateFromSeed } from '../keys/shachain';
import { getPublicKey } from '../crypto/ecdh';
import { decodeRevokeAndAckMessage } from '../message/channel-commitment';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import { MessageType as M } from '../message/types';
import type { IChannelReestablishMessage } from '../message/channel-reestablish';
import type { AssetSpliceConstructionEvent } from '../channel/asset-splice-construction';
import { assetSpliceSignatureFrame } from './asset-splice-release-replay';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IAssetSpliceLockEvent } from '../channel/asset-splice-lock';

type NonceEntry = { txid: string; nonce: string; generation?: number };
interface NonceEvent {
	kind: 'asset-reconnect-nonces';
	local: boolean;
	height: string;
	values: NonceEntry[];
}
const hex = (s: Buffer) => s.toString('hex');
const wireHash = (txid: string) => Buffer.from(txid, 'hex').reverse();
function previous(
	store: SqliteStorage,
	id: string,
	local: boolean,
	height: bigint
) {
	return store
		.readAssetSpliceJournal<NonceEvent>(id)
		.records.filter(
			(r) =>
				r.kind === 'asset-reconnect-nonces' &&
				r.local === local &&
				r.height === String(height)
		)
		.at(-1)?.values;
}
export function assetReconnectReservation(
	store: SqliteStorage,
	id: string,
	local: boolean,
	height: bigint,
	txid: string
): IFinalUpdateNonce | undefined {
	const e = previous(store, id, local, height)?.find((v) => v.txid === txid);
	return (
		e &&
		(local
			? e.generation === undefined
				? { pub: e.nonce, source: 'splice' }
				: { pub: e.nonce, source: 'update-reconnect', generation: e.generation }
			: { pub: e.nonce })
	);
}
function save(
	store: SqliteStorage,
	id: string,
	local: boolean,
	height: bigint,
	values: NonceEntry[]
) {
	if (
		JSON.stringify(previous(store, id, local, height)) !==
		JSON.stringify(values)
	)
		store.appendAssetSpliceEvent(id, store.readAssetSpliceJournal(id), {
			kind: 'asset-reconnect-nonces',
			local,
			height: String(height),
			values
		} satisfies NonceEvent);
}
function context(store: SqliteStorage, id: string) {
	const opening = store.loadFinalDaemonOpening(id)!;
	const c = opening.candidate,
		original = Transaction.fromHex(c.fundingTxHex).getId();
	const info = store.loadAssetSpliceFundingInfo(id);
	const selected: IFinalFundingReference = info.active?.candidate.funding ?? {
		fundingTxHex: c.fundingTxHex,
		fundingOutputIndex: c.fundingOutputIndex,
		localFundingKeyIndex: opening.session.channelKeyIndex,
		localFundingPubkey: c.localFundingPubkey,
		remoteFundingPubkey: c.remoteFundingPubkey
	};
	const members = [
		selected,
		...info.pending.map((r) => r.candidate.funding)
	].sort((a, b) =>
		Transaction.fromHex(a.fundingTxHex)
			.getId()
			.localeCompare(Transaction.fromHex(b.fundingTxHex).getId())
	);
	const construction = store
		.readAssetSpliceJournal<AssetSpliceConstructionEvent>(id)
		.records.filter(
			(r) => r.kind === 'construction-start' || r.kind === 'construction-frame'
		);
	const start = construction
		.filter(
			(
				r
			): r is Extract<
				AssetSpliceConstructionEvent,
				{ kind: 'construction-start' }
			> => r.kind === 'construction-start'
		)
		.at(-1);
	const expected = info.active?.candidate.fundingTxid ?? original;
	const locks = store
		.readAssetSpliceJournal<{
			kind: 'asset-splice-lock';
			event: IAssetSpliceLockEvent;
		}>(id)
		.records.filter(
			(r) => r.kind === 'asset-splice-lock' && r.event.kind === 'local'
		);
	const locked = locks.at(-1)?.event.terms.txid ?? expected;
	const history = assetUpdateHistory(store, id),
		secured = BigInt(history.latest?.height ?? 0);
	const rev = (height: bigint, local: boolean) =>
		history.stages.get(height + '/' + (local ? 'local-revoke' : 'peer-revoke'));
	const peerRevoke = rev(secured, false)
		? secured
		: secured > 0n
		? secured - 1n
		: 0n;
	return {
		opening,
		original,
		info,
		members,
		construction,
		start,
		expected,
		locked,
		history,
		secured,
		rev,
		peerRevoke
	};
}
export function assetSpliceReestablish(
	store: SqliteStorage,
	authority: FinalOpeningAuthority,
	id: string,
	root: BIP32Interface,
	reportLock: boolean
): IChannelReestablishMessage {
	const c = context(store, id),
		height = c.secured + 1n;
	const keys = deriveChannelKeys(root, 1, c.opening.session.channelKeyIndex);
	const frozen = c.history.stages.get(height + '/offer');
	const offered: string[] | undefined =
		frozen && JSON.parse(Buffer.from(frozen, 'hex').toString()).nonces;
	const values = c.members.map((funding, i) => {
		const tx = Transaction.fromHex(funding.fundingTxHex),
			txid = tx.getId();
		// Preserve the exact verification nonce once either side can have a signed offer.
		if (offered) {
			const old = previous(store, id, true, height)?.find(
				(v) => v.txid === txid
			);
			const nonce = offered[i];
			if (!nonce || (old && old.nonce !== nonce))
				throw Error('Stored asset offer conflicts with reconnect nonce');
			return old ?? { txid, nonce };
		}
		const key = deriveChannelKeys(root, 1, funding.localFundingKeyIndex),
			locator = spliceCommitmentNonceContext(
				id,
				tx.getHash(),
				funding.fundingOutputIndex
			);
		if (hex(key.channelBasepoints.fundingPubkey) !== funding.localFundingPubkey)
			throw Error('Invalid asset reconnect funding locator');
		const promise = authority.advanceReestablishNonce(
			'asset-update-reconnect/' + id + '/' + txid,
			hex(locator),
			undefined,
			(generation) =>
				Buffer.from(
					updateVerificationNonce(
						authority.nonceContext(locator),
						key.fundingPrivkey,
						Number(height),
						{ source: 'update-reconnect', pub: '', generation }
					)
				)
		);
		return { txid, ...promise };
	});
	save(store, id, true, height, values);
	const peerSecret = c.rev(c.peerRevoke, false);
	const msg: IChannelReestablishMessage = {
		channelId: Buffer.from(id, 'hex'),
		nextCommitmentNumber: height,
		nextRevocationNumber: c.peerRevoke,
		myCurrentPerCommitmentPoint: getPublicKey(
			generateFromSeed(keys.perCommitmentSeed, MAX_INDEX - c.secured)
		),
		yourLastPerCommitmentSecret: peerSecret
			? decodeRevokeAndAckMessage(Buffer.from(peerSecret, 'hex'), {
					finalTaproot: true
			  }).perCommitmentSecret
			: Buffer.alloc(32),
		nextLocalNonces: values.map((v) => ({
			fundingTxid: wireHash(v.txid),
			nonce: Buffer.from(v.nonce, 'hex')
		})),
		...(reportLock && {
			myCurrentFundingLocked: { txid: wireHash(c.locked), retransmitFlags: 0 }
		})
	};
	const s = c.start;
	if (
		s &&
		assetSpliceSignatureFrame(
			store,
			id,
			s.finalDigest,
			true,
			M.COMMITMENT_SIGNED
		) &&
		!assetSpliceSignatureFrame(store, id, s.finalDigest, false, M.TX_SIGNATURES)
	) {
		msg.nextFundingTxid = wireHash(s.txid);
		msg.nextFundingRetransmitFlags = assetSpliceSignatureFrame(
			store,
			id,
			s.finalDigest,
			false,
			M.COMMITMENT_SIGNED
		)
			? 0
			: 1;
		if (msg.nextFundingRetransmitFlags)
			msg.currentCommitNonce = decodeTxCompleteMessage(
				Buffer.from(s.localComplete, 'hex'),
				{ taproot: true }
			).commitNonces!.current;
	}
	return msg;
}
export function acceptAssetSpliceReestablish(
	store: SqliteStorage,
	id: string,
	root: BIP32Interface,
	msg: IChannelReestablishMessage
) {
	const c = context(store, id),
		localNext = c.secured + 1n,
		remote = msg.nextCommitmentNumber;
	const keys = deriveChannelKeys(root, 1, c.opening.session.channelKeyIndex);
	const sentHeight = c.rev(c.secured, true)
		? c.secured
		: c.secured > 0n
		? c.secured - 1n
		: 0n;
	if (
		hex(msg.channelId) !== id ||
		msg.ffor ||
		remote < 1n ||
		remote > MAX_INDEX ||
		remote + 1n < localNext ||
		remote > localNext + 1n ||
		(remote > localNext &&
			!c.history.stages.has(localNext + '/local-commits')) ||
		msg.nextRevocationNumber > sentHeight ||
		msg.nextRevocationNumber + 1n < sentHeight ||
		(msg.nextRevocationNumber > 0n && !c.rev(msg.nextRevocationNumber, true)) ||
		!msg.yourLastPerCommitmentSecret.equals(
			msg.nextRevocationNumber
				? generateFromSeed(
						keys.perCommitmentSeed,
						MAX_INDEX - msg.nextRevocationNumber + 1n
				  )
				: Buffer.alloc(32)
		)
	)
		throw Error(
			'Asset reconnect commitment or revocation counter differs from the original device'
		);
	// Both sides completed round N before a record at N: the old era's
	// revoke_and_ack names the old funding's nonce and cannot be resent.
	if (
		c.history.seedHeight !== undefined &&
		msg.nextRevocationNumber < c.history.seedHeight
	)
		throw Error('Peer reestablish is behind the channel type record');
	const prior = remote - 1n;
	const priorRevoke = c.rev(prior - 1n, false);
	const point =
		prior === 0n
			? c.opening.session.terms.remoteBasepoints.firstPerCommitmentPoint
			: c.history.states.get(prior)?.members[0]?.remoteRecovery.point ??
			  (prior === 1n
					? c.opening.session.remoteSecondPerCommitmentPoint
					: priorRevoke &&
					  hex(
							decodeRevokeAndAckMessage(Buffer.from(priorRevoke, 'hex'), {
								finalTaproot: true
							}).nextPerCommitmentPoint
					  ));
	if (point !== hex(msg.myCurrentPerCommitmentPoint))
		throw Error('Asset reconnect holder point differs from the secured state');
	const fundingIds = c.members.map((v) =>
		Transaction.fromHex(v.fundingTxHex).getId()
	);
	const known = new Set([
		...fundingIds,
		c.original,
		...c.info.previousFundingTxids,
		...c.construction.map((f) => f.txid)
	]);
	const locked = msg.myCurrentFundingLocked;
	const next = c.start;
	if (
		(locked &&
			(locked.retransmitFlags !== 0 ||
				!known.has(hex(Buffer.from(locked.txid).reverse())))) ||
		(msg.nextFundingTxid &&
			(!next || !msg.nextFundingTxid.equals(wireHash(next.txid)))) ||
		(msg.nextFundingRetransmitFlags ?? 0) > 1 ||
		!!msg.currentCommitNonce !== !!msg.nextFundingRetransmitFlags
	)
		throw Error('Asset reconnect announced an unknown funding');
	if (msg.currentCommitNonce) {
		const wire = c.construction
			.filter(
				(r) =>
					r.kind === 'construction-frame' &&
					r.finalDigest === next?.finalDigest &&
					!r.local &&
					r.type === M.TX_COMPLETE
			)
			.at(-1);
		if (
			wire?.kind !== 'construction-frame' ||
			!decodeTxCompleteMessage(Buffer.from(wire.payload, 'hex'), {
				taproot: true
			}).commitNonces?.current.equals(msg.currentCommitNonce)
		)
			throw Error('Asset reconnect changed an interactive verification nonce');
	}
	const nonces = msg.nextLocalNonces ?? [];
	const values = nonces.map((n) => ({
		txid: hex(Buffer.from(n.fundingTxid).reverse()),
		nonce: hex(n.nonce)
	}));
	if (
		!values.length ||
		new Set(values.map((v) => v.txid)).size !== values.length ||
		new Set(values.map((v) => v.nonce)).size !== values.length ||
		values.some((v) => !known.has(v.txid)) ||
		(!values.some((v) => fundingIds.includes(v.txid)) &&
			!values.some((v) => v.txid === c.info.active?.parent.fundingTxid))
	)
		throw Error('Asset reconnect verification funding set differs');
	for (const n of nonces) checkUpdateNonce(n.nonce);
	// A peer can cross our splice_locked or funding witness while disconnected. Its next signed offer still has to match our full elected membership.
	const offered = c.history.stages.get(remote + '/peer-offer');
	if (offered) {
		const fixed: string[] = JSON.parse(
			Buffer.from(offered, 'hex').toString()
		).nonces;
		if (
			values.length !== fixed.length ||
			values.some(
				(v, i) =>
					v.nonce !== fixed[i] ||
					v.txid !==
						(c.history.states.get(remote)?.members.map((m) => m.fundingTxid) ??
							fundingIds)[i]
			)
		)
			throw Error('Asset reconnect changed a peer verification offer');
	}
	save(store, id, false, remote, values);
}
