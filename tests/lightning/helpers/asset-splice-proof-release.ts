import { mnemonicToSeedSync } from 'bip39';
import { payments, Transaction } from 'bitcoinjs-lib';
import path from 'path';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession
} from '../../../src/lightning/channel/commitment-musig';
import {
	buildAssetOpeningCommitment,
	buildAssetSpliceCommitment
} from '../../../src/lightning/channel/final-opening-commitment';
import {
	buildFinalSpliceCandidate,
	type IFinalSpliceTerms
} from '../../../src/lightning/channel/final-splice-candidate';
import {
	finalSpliceSharedNonce,
	signFinalSpliceFunding
} from '../../../src/lightning/channel/final-splice-funding';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import { generateNonce } from '../../../src/lightning/crypto/musig';
import {
	ASSET_OPENING_TYPE_HEX,
	ASSET_SPLICE_RECOVERY_TYPE_HEX
} from '../../../src/lightning/features/asset-opening';
import {
	bip32RootFromSeed,
	deriveChannelKeys
} from '../../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import {
	retainAssetSpliceExitProofs,
	type IAssetSpliceExitProofs
} from '../../../src/lightning/storage/asset-splice-exit-proofs';
import type { FinalOpeningAuthority } from '../../../src/lightning/storage/final-opening-authority';
import { generateFinalDaemonWallet } from '../../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { inputTransaction } from './final-opening';
import { otherOpeningView } from './final-opening-commitment';
import { boundParticipant, signingFixture } from './final-opening-signing';
import { walletSigner } from './final-update-pair';

function device(dir: string, name: string, generation: 4 | 5) {
	const fresh = generateFinalDaemonWallet(
		false,
		false,
		generation === 4,
		generation === 5
	);
	const seed = mnemonicToSeedSync(fresh.mnemonic);
	const party = boundParticipant(bip32RootFromSeed(seed), 1, fresh.binding);
	const file = path.join(dir, name);
	return {
		party,
		seed,
		file,
		store: SqliteStorage.createFinalWallet(file, fresh.binding)
	};
}
function authority(store: SqliteStorage): FinalOpeningAuthority {
	return (store as unknown as { openingAuthority: FinalOpeningAuthority })
		.openingAuthority;
}

export const finalDigest = 'f1'.repeat(32);
const parentRoot = Buffer.alloc(32, 41),
	candidateRoot = Buffer.alloc(32, 43);
const leaves = {
	toLocal: { script: Buffer.from('6a01aa', 'hex') },
	toRemote: { script: Buffer.from('6a01bb', 'hex') }
};
export const branchNames = ['parent', 'candidate'] as const;
type AlternateContext = {
	store: SqliteStorage;
	finalDigest: Buffer;
	stateNumber: bigint;
	parentRemote: Transaction;
	candidateRemote: Transaction;
};
export function setupAssetSpliceProofs(
	dir: string,
	updateLimits?: import('../../../src/lightning/storage/final-channel-updates').IFinalUpdateLimits,
	generation: 4 | 5 = 4
) {
	const devices = [
		device(dir, 'left', generation),
		device(dir, 'right', generation)
	];
	const parties = devices.map((d) => d.party);
	const oldKeys = parties.map((p) => p.keys);
	const newKeys = parties.map((p) => deriveChannelKeys(p.root, 1, 2));
	const {
		candidate: opening,
		terms: openingTerms,
		id,
		funding: parent
	} = signingFixture(false, parties[0], parties[1]);
	const rooted = (keys: typeof oldKeys, root: Buffer) =>
		createTaprootFundingScript(
			keys[0].channelBasepoints.fundingPubkey,
			keys[1].channelBasepoints.fundingPubkey,
			undefined,
			root
		).p2trOutput;
	opening.channelType =
		generation === 5 ? ASSET_SPLICE_RECOVERY_TYPE_HEX : ASSET_OPENING_TYPE_HEX;
	for (const [i, input] of opening.inputs.entries()) {
		const previous = Transaction.fromHex(input.prevTxHex);
		previous.outs[0].script = payments.p2wpkh({
			pubkey: oldKeys[i].channelBasepoints.fundingPubkey
		}).output!;
		input.prevTxHex = previous.toHex();
		parent.ins[i].hash = previous.getHash();
	}
	parent.outs[opening.fundingOutputIndex].script = rooted(oldKeys, parentRoot);
	opening.fundingTxHex = parent.toHex();
	const fromOther = otherOpeningView(opening, openingTerms);
	const openingViews = [{ candidate: opening, terms: openingTerms }, fromOther];
	const side = (proofs: string) => ({
		toLocal: { script: '6a01aa' },
		toRemote: { script: '6a01bb' },
		proofs
	});
	for (const [i, d] of devices.entries()) {
		d.store.allocateFinalChannelKeyIndex(1);
		d.store.rememberAssetOpeningSession(
			openingViews[i].candidate,
			parties[1 - i].binding.nodeId,
			openingViews[i].terms,
			1,
			getPublicKey(
				generateFromSeed(parties[1 - i].keys.perCommitmentSeed, MAX_INDEX - 1n)
			).toString('hex'),
			{
				fundingRoot: parentRoot.toString('hex'),
				layoutDigest: '11'.repeat(32),
				finalDigest: '22'.repeat(32),
				fundingProofs: 'a0b1',
				local: side(i ? 'a2' : 'a1'),
				remote: side(i ? 'a1' : 'a2')
			},
			updateLimits ?? {
				local: {
					htlcMinimumMsat: '1',
					maxHtlcValueInFlightMsat: '100000000',
					maxAcceptedHtlcs: 20,
					channelReserveSats: '1400'
				},
				remote: {
					htlcMinimumMsat: '1',
					maxHtlcValueInFlightMsat: '100000000',
					maxAcceptedHtlcs: 20,
					channelReserveSats: '1400'
				}
			}
		);
	}
	function fundOpening(): void {
		const nonces = devices.map(({ store }, i) =>
			store.finalOpeningTxComplete(id, oldKeys[i].fundingPrivkey)
		);
		for (const [i, { store }] of devices.entries())
			store.rememberFinalPeerTxComplete(id, nonces[1 - i]);
		const shares = devices.map(({ store }, i) =>
			store.signFinalPeerCommitment(
				id,
				openingViews[i].terms,
				parties[i].root,
				1
			)
		);
		for (const [i, { store }] of devices.entries())
			store.acceptFinalPeerCommitment(
				id,
				openingViews[i].terms,
				parties[i].root,
				1,
				shares[1 - i]
			);
		for (const [i, { store }] of devices.entries()) {
			const { tx, local, prevouts } = store.prepareAssetOpeningWitnesses(id);
			const signer = walletSigner(oldKeys[i].fundingPrivkey, i, []);
			const wire = store.storeAssetOpeningWitnesses(
				id,
				signer(tx, local, prevouts)
			);
			devices[1 - i].store.rememberFinalPeerTxSignatures(id, wire);
		}
	}
	const external = inputTransaction(123, 20500);
	const walletScript = payments.p2wpkh({
		pubkey: oldKeys[0].channelBasepoints.fundingPubkey
	}).output!;
	external.outs[0].script = walletScript;
	const terms = devices.map(
		(_, i): IFinalSpliceTerms => ({
			parent,
			parentIndex: opening.fundingOutputIndex,
			oldLocalKey: oldKeys[i].channelBasepoints.fundingPubkey,
			oldPeerKey: oldKeys[1 - i].channelBasepoints.fundingPubkey,
			newLocalKey: newKeys[i].channelBasepoints.fundingPubkey,
			newPeerKey: newKeys[1 - i].channelBasepoints.fundingPubkey,
			localIsSpliceInitiator: i === 0,
			localDelta: i === 0 ? 10000n : 0n,
			peerDelta: i === 0 ? 0n : 10000n,
			localFeeBudget: i === 0 ? 500n : 0n,
			feerate: 253,
			dust: 354n,
			locktime: 0,
			assetFundingRoots: { parent: parentRoot, candidate: candidateRoot }
		})
	);
	const inputs = [
		{
			serialId: 0n,
			prevTxid: parent.getHash(),
			prevOutputIndex: opening.fundingOutputIndex,
			sequence: 0xfffffffd,
			isShared: true
		},
		{
			serialId: 2n,
			prevTxid: external.getHash(),
			prevTx: external.toBuffer(),
			prevOutputIndex: 0,
			sequence: 0xfffffffd
		}
	];
	const outputs = [
		{ serialId: 4n, scriptPubkey: walletScript, amountSats: 10000n },
		{
			serialId: 6n,
			scriptPubkey: rooted(newKeys, candidateRoot),
			amountSats: 150000n
		}
	];
	const candidates = terms.map((t) =>
		buildFinalSpliceCandidate(t, inputs, outputs)
	);
	const candidate = candidates[0];
	function exit(
		holder: number,
		old: boolean,
		source = old ? parent : candidate.tx,
		height = 0n
	) {
		const index = old ? opening.fundingOutputIndex : candidate.fundingIndex;
		const keys = old ? oldKeys : newKeys;
		const root = old ? parentRoot : candidateRoot;
		const name = holder === 0 ? 'local' : 'remote';
		const point = getPublicKey(
			generateFromSeed(
				parties[holder].keys.perCommitmentSeed,
				MAX_INDEX - height
			)
		);
		const built =
			old && height === 0n
				? buildAssetOpeningCommitment(opening, openingTerms, name, {
						fundingRoot: root,
						...leaves
				  })
				: buildAssetSpliceCommitment(
						opening,
						openingTerms,
						name,
						point,
						height,
						{
							localBalanceMsat: old ? 90000000n : 100000000n,
							remoteBalanceMsat: 50000000n
						},
						[],
						{
							fundingTxHex: source.toHex(),
							fundingOutputIndex: index,
							localFundingPubkey:
								keys[0].channelBasepoints.fundingPubkey.toString('hex'),
							remoteFundingPubkey:
								keys[1].channelBasepoints.fundingPubkey.toString('hex'),
							localFundingKeyIndex: old ? 1 : 2
						},
						parentRoot,
						{ fundingRoot: root, ...leaves }
				  );
		const expected = built.tx;
		const prev = source.outs[index];
		const digest = expected.hashForWitnessV1(
			0,
			[prev.script],
			[prev.value],
			Transaction.SIGHASH_DEFAULT
		);
		const nonces = keys.map((k) =>
			generateNonce({
				secretKey: k.fundingPrivkey,
				publicKey: k.channelBasepoints.fundingPubkey,
				msg: digest
			})
		);
		const session = startCommitmentSigningSession(
			digest,
			keys[0].channelBasepoints.fundingPubkey,
			keys[1].channelBasepoints.fundingPubkey,
			nonces[0],
			Buffer.from(nonces[1]),
			root
		);
		const shares = keys.map((k, j) =>
			partialSignCommitment(session, k.fundingPrivkey, nonces[j])
		);
		const signed = expected.clone();
		signed.setWitness(0, [
			aggregateCommitmentSig(session, shares[0], shares[1])
		]);
		return { expected, signed, point, outputMap: built.outputMap };
	}
	const views = parties.map((_, i) => ({
		parent: exit(i, true),
		candidate: exit(i, false)
	}));
	const nonces = candidates.map((c, i) =>
		finalSpliceSharedNonce(
			c,
			oldKeys[i].fundingPrivkey,
			authority(devices[i].store)
		)
	);
	const calls: number[] = [];
	const witness = walletSigner(oldKeys[0].fundingPrivkey, 1, calls);
	function evidence(i: number, height = 0n): IAssetSpliceExitProofs {
		const atHeight =
			height === 0n
				? views
				: parties.map((_, j) => ({
						parent: exit(j, true, parent, height),
						candidate: exit(j, false, candidate.tx, height)
				  }));
		function branch(name: (typeof branchNames)[number]) {
			const old = name === 'parent';
			const keys = old ? oldKeys : newKeys;
			const funding = {
				fundingTxHex: (old ? parent : candidate.tx).toHex(),
				fundingOutputIndex: old
					? opening.fundingOutputIndex
					: candidate.fundingIndex,
				localFundingPubkey:
					keys[i].channelBasepoints.fundingPubkey.toString('hex'),
				remoteFundingPubkey:
					keys[1 - i].channelBasepoints.fundingPubkey.toString('hex'),
				localFundingKeyIndex: old ? 1 : 2
			};
			const recovery = (holder: number) => ({
				point: atHeight[holder][name].point.toString('hex'),
				localBalanceMsat: String(i ? 50000000 : old ? 90000000 : 100000000),
				remoteBalanceMsat: String(i ? (old ? 90000000 : 100000000) : 50000000),
				toLocal: { script: leaves.toLocal.script.toString('hex') },
				toRemote: { script: leaves.toRemote.script.toString('hex') },
				ownedOutputIndex:
					(holder === i
						? atHeight[holder][name].outputMap.toLocal
						: atHeight[holder][name].outputMap.toRemote) ?? null,
				htlcs: []
			});
			return {
				minimumDepth: 3,
				funding,
				localRecovery: recovery(i),
				remoteRecovery: recovery(1 - i),
				fundingTxid: (old ? parent : candidate.tx).getId(),
				outputIndex: old ? opening.fundingOutputIndex : candidate.fundingIndex,
				fundingRoot: (old ? parentRoot : candidateRoot).toString('hex'),
				fundingProofs: old ? 'a0b1' : 'b0c1',
				localCommitment: atHeight[i][name].signed.toHex(),
				remoteCommitment: atHeight[1 - i][name].expected.toHex(),
				localProofs: (old ? 'a' : 'b') + (i + 1),
				remoteProofs: (old ? 'a' : 'b') + (2 - i)
			};
		}
		return {
			minimumDepth: 3,
			channelId: id,
			finalDigest,
			stateNumber: height.toString(),
			parent: branch('parent'),
			candidate: branch('candidate')
		};
	}
	function otherCandidate(i: number) {
		const other = candidate.tx.clone();
		other.locktime++;
		const result = evidence(i);
		result.candidate = {
			...result.candidate,
			funding: { ...result.candidate.funding, fundingTxHex: other.toHex() },
			fundingTxid: other.getId(),
			localCommitment: exit(i, false, other).signed.toHex(),
			remoteCommitment: exit(1 - i, false, other).expected.toHex()
		};
		return result;
	}
	function context(i: number): AlternateContext {
		return {
			store: devices[i].store,
			finalDigest: Buffer.from(finalDigest, 'hex'),
			stateNumber: 0n,
			parentRemote: views[1 - i].parent.expected,
			candidateRemote: views[1 - i].candidate.expected
		};
	}
	function sign(
		i: number,
		ctx: AlternateContext | undefined,
		selected = views[i],
		signer: typeof witness = (tx, indices, prevouts) => {
			if (i === 0) return witness(tx, indices, prevouts);
			if (indices.length) throw Error('Unexpected external input on acceptor');
			return [];
		}
	) {
		return signFinalSpliceFunding(
			candidates[i],
			terms[i],
			Buffer.from(id, 'hex'),
			oldKeys[i].fundingPrivkey,
			nonces[i],
			nonces[1 - i],
			authority(devices[i].store),
			selected,
			signer,
			ctx
		);
	}
	function retain(i: number, e = evidence(i)) {
		retainAssetSpliceExitProofs(devices[i].store, id, e);
	}
	return {
		fundOpening,
		inputs,
		outputs,
		devices,
		id,
		candidates,
		views,
		terms,
		nonces,
		calls,
		sign,
		context,
		evidence,
		otherCandidate,
		retain
	};
}
