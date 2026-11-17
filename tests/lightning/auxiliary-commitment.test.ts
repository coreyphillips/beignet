/**
 * Commitments with auxiliary leaves (issue #2093, step 6).
 *
 * An ordinary channel must build, sign and encode exactly what it did
 * before: the digests below were taken from the code before auxiliary
 * leaves reached the script and commitment builders. An asset channel
 * commits each asset-bearing output to the provider's leaf, signs for the
 * funding key tweaked by its asset root, carries the provider's signatures
 * in commitment_signed, and fails closed whenever any of that is missing
 * or wrong.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	rootHashFromPath,
	tapTweakHash
} from 'bitcoinjs-lib/src/payments/bip341';
import { ecc } from '../../src/utils/ecc';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	signRemoteHtlcSignaturesTaproot,
	verifyRemoteHtlcSignaturesTaproot
} from '../../src/lightning/channel/commitment-builder';
import { getPerCommitmentPoint } from '../../src/lightning/channel/channel-helpers';
import { taprootCommitmentSighash } from '../../src/lightning/channel/commitment-musig';
import type { IChannelState } from '../../src/lightning/channel/channel-state';
import type { ITaprootAuxLeaf } from '../../src/lightning/channel/auxiliary';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	assetHtlcSighashType,
	isAnchorChannel,
	isFixedAssetHtlcChannel,
	isOverlayChannel,
	isRevokedChildCustodyChannel,
	isTaprootChannel,
	hasSimpleTaprootBit
} from '../../src/lightning/channel/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { deriveTaprootFundingKey } from '../../src/lightning/crypto/musig';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { MessageType } from '../../src/lightning/message/types';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput
} from '../../src/lightning/script/commitment-taproot';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { tapleafHash } from '../../src/lightning/script/htlc-taproot';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	commitmentDigests,
	commitmentSignedDigest,
	taprootScriptDigest
} from './helpers/auxiliary-commitment-fixture';
import {
	ASSET_FUNDING_ROOT,
	amountRecord,
	hash,
	leafFor,
	overlayChannelType,
	taprootPair
} from './helpers/auxiliary-pair';
import type { IAssetPair } from './helpers/auxiliary-pair';
import { writableState } from './helpers/writable-state';

bitcoin.initEccLib(ecc);

const sha256 = (data: string): string =>
	crypto.createHash('sha256').update(data).digest('hex');
const key = (n: number): Buffer => getPublicKey(Buffer.alloc(32, n));

/** The type of an ordinary simple taproot channel. */
function simpleTaprootType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT);
	return flags.toBuffer();
}

/** The x-only key a taproot output pays to. */
const outputKeyOf = (script: Buffer): Buffer => script.subarray(2);

/** Whether `leaf` at `controlBlock` is committed to by the output `script`. */
function commits(
	script: Buffer,
	internalKey: Buffer,
	leaf: { script: Buffer; controlBlock: Buffer; leafVersion: number }
): boolean {
	const root = rootHashFromPath(
		leaf.controlBlock,
		tapleafHash(leaf.script, leaf.leafVersion)
	);
	const tweaked = ecc.xOnlyPointAddTweak(
		internalKey,
		tapTweakHash(internalKey, root)
	);
	return (
		!!tweaked && Buffer.from(tweaked.xOnlyPubkey).equals(outputKeyOf(script))
	);
}

/**
 * Put the same asset HTLC, offered by Alice, into both channels the way a
 * committed add leaves it, without the wire exchange a later step adds.
 */
function addAssetHtlc(
	pair: IAssetPair,
	id: bigint,
	amountMsat: bigint,
	assetAmount: bigint | undefined
): void {
	const paymentHash = hash(`asset htlc ${id}`);
	for (const [channel, direction] of [
		[pair.aliceChannel, HtlcDirection.OFFERED],
		[pair.bobChannel, HtlcDirection.RECEIVED]
	] as const) {
		const state = writableState(channel);
		const offered = direction === HtlcDirection.OFFERED;
		state.htlcs.set(`${offered ? 'offered' : 'received'}-${id}`, {
			id,
			amountMsat,
			paymentHash,
			cltvExpiry: 800_000,
			onionRoutingPacket: Buffer.alloc(1366),
			direction,
			state: HtlcState.COMMITTED,
			...(assetAmount !== undefined
				? {
						customRecords: amountRecord(assetAmount),
						auxiliaryAmount: assetAmount
				  }
				: {})
		});
		if (offered) {
			state.localBalanceMsat -= amountMsat;
			state.auxiliaryState!.localBalance -= assetAmount ?? 0n;
		} else {
			state.remoteBalanceMsat -= amountMsat;
			state.auxiliaryState!.remoteBalance -= assetAmount ?? 0n;
		}
	}
}

/** Bob's next commitment as each side builds it. */
function bobNextCommitment(pair: IAssetPair): {
	number: bigint;
	point: Buffer;
	bobState: IChannelState;
	aliceState: IChannelState;
} {
	const bobState = writableState(pair.bobChannel);
	const number = bobState.localCommitmentNumber + 1n;
	return {
		number,
		point: getPerCommitmentPoint(bobState.localPerCommitmentSeed, number),
		bobState,
		aliceState: writableState(pair.aliceChannel)
	};
}

function verifyFundingSpend(
	tx: bitcoin.Transaction,
	state: IChannelState
): void {
	const funding = createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		undefined,
		state.fundingTaprootMerkleRoot
	);
	expect(tx.ins[0].witness.length).to.equal(1);
	expect(
		ecc.verifySchnorr(
			taprootCommitmentSighash(
				tx,
				funding.p2trOutput,
				Number(state.fundingSatoshis)
			),
			funding.outputKey,
			tx.ins[0].witness[0]
		)
	).to.equal(true);
}

describe('commitments with auxiliary leaves', function () {
	this.timeout(20000);

	describe('an ordinary channel', () => {
		// Taken with the code as it stood before auxiliary leaves reached the
		// builders, from the same fixtures.
		const BEFORE = {
			taproot: {
				localTx:
					'593c9a6afe1713eb37a842792d8494612f91f7cf337255ae9d30b78c8ba9bbbd',
				remoteTx:
					'75f92db484b296e1b0480105fe907fe2a96b39d31705db01541101efde56b7c5',
				signatures:
					'823e7a9a95c32e47617f30ab0f9698732482a0e0f07b08b86b5a95a215f1a289'
			},
			anchors: {
				localTx:
					'3fc95432f16cdc3502490a829da38b765a2012bff964c85184b9ca5839a6126a',
				remoteTx:
					'c6c5a43e56bbb255e8bf0c58310739bca2d3b5d8bf083a5432ae7f3cb22be362',
				signatures:
					'7871909c3cb825e4870f2f0438aebc57be3dee3d75ea76e65cf288965cdf631d'
			}
		};

		for (const kind of ['taproot', 'anchors'] as const) {
			it(`builds and signs the same ${kind} commitment bytes as before`, () => {
				const digests = commitmentDigests(kind);
				expect(digests.localTx.length).to.equal(618);
				expect(sha256(digests.localTx)).to.equal(BEFORE[kind].localTx);
				expect(sha256(digests.remoteTx)).to.equal(BEFORE[kind].remoteTx);
				expect(digests.localHtlcOutputs).to.deep.equal([2, 3]);
				expect(digests.remoteHtlcOutputs).to.deep.equal([2, 3]);
				expect(digests.signatures).to.equal(BEFORE[kind].signatures);
			});
		}

		it('builds the same taproot outputs, control blocks and second-level transactions as before', () => {
			expect(taprootScriptDigest()).to.equal(
				'f8c248ccd0d0d34652aa91df48b058397d9b1ed1f7bae8b3771cbec19a716ef6'
			);
		});

		it('encodes commitment_signed to the same bytes as before', () => {
			expect(commitmentSignedDigest()).to.equal(
				'18debb0a77b2e61880db535ab6eba04ec240ffaa526c891892f017d988bd95de'
			);
		});

		it('gains no auxiliary key on its built commitment or its HTLC outputs', () => {
			const pair = taprootPair(40, { asset: false });
			const state = writableState(pair.aliceChannel);
			state.htlcs.set('offered-0', {
				id: 0n,
				amountMsat: 50_000_000n,
				paymentHash: hash('ordinary htlc'),
				cltvExpiry: 800_000,
				onionRoutingPacket: Buffer.alloc(1366),
				direction: HtlcDirection.OFFERED,
				state: HtlcState.COMMITTED
			});
			state.localBalanceMsat -= 50_000_000n;
			const point = getPerCommitmentPoint(state.localPerCommitmentSeed, 1n);
			for (const built of [
				buildLocalCommitment(state, point, 1n),
				buildRemoteCommitment(state, state.remoteCurrentPerCommitmentPoint!, 1n)
			]) {
				expect(built).to.not.have.property('auxiliary');
				expect(built.htlcOutputs.length).to.equal(1);
				expect(built.htlcOutputs[0]).to.not.have.property('customRecords');
				expect(built.htlcOutputs[0]).to.not.have.property('auxiliaryAmount');
			}
		});

		it('exchanges commitment_signed with no custom record and keeps no asset view', () => {
			const pair = taprootPair(42, { asset: false });
			expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);
			const signed = pair.wire.filter(
				(m) => m.type === MessageType.COMMITMENT_SIGNED
			);
			expect(signed.length).to.equal(2);
			for (const message of signed) {
				// Readable by the standard decoder: no type at or above 65536.
				expect(
					decodeCommitmentSignedMessage(message.payload)
				).to.not.have.property('customRecords');
			}
			for (const channel of [pair.aliceChannel, pair.bobChannel]) {
				const state = channel.getFullState();
				expect(state.state).to.equal(ChannelState.NORMAL);
				expect(state).to.not.have.property('auxiliaryState');
				expect(state).to.not.have.property('lastSentAuxiliaryRecords');
			}
		});

		it('still fails a commitment_signed that carries an even custom record', () => {
			const pair = taprootPair(44, { asset: false });
			pair.intercept.fn = (from, type, payload): Buffer => {
				if (from !== 'alice' || type !== MessageType.COMMITMENT_SIGNED) {
					return payload;
				}
				const message = decodeCommitmentSignedMessage(payload);
				return encodeCommitmentSignedMessage({
					...message,
					customRecords: new Map([[65538n, Buffer.alloc(32, 7)]])
				});
			};
			const before = pair.bobChannel.getFullState().localCommitmentNumber;
			pair.alice.updateChannelFee(pair.id, 700);
			// The standard decoder refuses the unknown even type, so Bob never
			// adopts the commitment and never revokes.
			expect(pair.bobChannel.getFullState().localCommitmentNumber).to.equal(
				before
			);
			expect(
				pair.wire.some(
					(m) => m.from === 'bob' && m.type === MessageType.REVOKE_AND_ACK
				)
			).to.equal(false);
		});
	});

	describe('channel type predicates', () => {
		it('treats the overlay as a taproot, anchor-style commitment', () => {
			const overlay = overlayChannelType();
			expect(isOverlayChannel(overlay)).to.equal(true);
			expect(isTaprootChannel(overlay)).to.equal(true);
			expect(isAnchorChannel(overlay)).to.equal(true);
			// A type a peer has only proposed is not taken for simple taproot.
			expect(hasSimpleTaprootBit(overlay)).to.equal(false);
			expect(hasSimpleTaprootBit(null)).to.equal(false);
		});

		it('reads fixed HTLC outputs and child custody from the channel type alone', () => {
			const plain = overlayChannelType();
			const fixed = overlayChannelType(Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS);
			const custody = overlayChannelType(
				Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
				Feature.OPTION_ASSET_CHILD_CUSTODY
			);
			const custodyAlone = overlayChannelType(
				Feature.OPTION_ASSET_CHILD_CUSTODY
			);
			expect(isFixedAssetHtlcChannel(plain)).to.equal(false);
			expect(isFixedAssetHtlcChannel(fixed)).to.equal(true);
			expect(isRevokedChildCustodyChannel(fixed)).to.equal(false);
			expect(isRevokedChildCustodyChannel(custody)).to.equal(true);
			// Child custody means nothing without fixed HTLC outputs.
			expect(isRevokedChildCustodyChannel(custodyAlone)).to.equal(false);
			expect(assetHtlcSighashType(plain)).to.equal(0x83);
			expect(assetHtlcSighashType(fixed)).to.equal(0x81);
			// No ordinary channel signs anything but SINGLE|ANYONECANPAY.
			expect(assetHtlcSighashType(null)).to.equal(0x83);
			const simpleTaproot = simpleTaprootType();
			expect(isTaprootChannel(simpleTaproot)).to.equal(true);
			expect(assetHtlcSighashType(simpleTaproot)).to.equal(0x83);
		});
	});

	describe('taproot outputs with an auxiliary leaf', () => {
		const leaf = leafFor('asset commitment');
		const paymentHash = Buffer.alloc(32, 0x42);

		it('commits every output to its ordinary leaves and to the auxiliary leaf', () => {
			const numsInternal = (spend: { controlBlock: Buffer }): Buffer =>
				spend.controlBlock.subarray(1, 33);

			const plainLocal = buildTaprootToLocalOutput(key(1), key(2), 144);
			const local = buildTaprootToLocalOutput(
				key(1),
				key(2),
				144,
				undefined,
				leaf
			);
			expect(local.output.equals(plainLocal.output)).to.equal(false);
			// Same leaf scripts, one more step in each control block.
			expect(local.delay.script).to.deep.equal(plainLocal.delay.script);
			expect(local.delay.controlBlock.length).to.equal(
				plainLocal.delay.controlBlock.length + 32
			);
			for (const spend of [local.delay, local.revoke]) {
				expect(commits(local.output, numsInternal(spend), spend)).to.equal(
					true
				);
			}
			// The auxiliary leaf is the sibling of the ordinary tree.
			expect(
				local.delay.controlBlock.subarray(-32).equals(tapleafHash(leaf.script))
			).to.equal(true);

			const remote = buildTaprootToRemoteOutput(key(3), undefined, leaf);
			expect(
				remote.output.equals(buildTaprootToRemoteOutput(key(3)).output)
			).to.equal(false);
			expect(
				commits(remote.output, numsInternal(remote.spend), remote.spend)
			).to.equal(true);

			for (const htlc of [
				buildTaprootOfferedHtlcOutput(
					key(1),
					key(4),
					key(5),
					paymentHash,
					undefined,
					leaf
				),
				buildTaprootReceivedHtlcOutput(
					key(1),
					key(4),
					key(5),
					paymentHash,
					800_000,
					undefined,
					leaf
				)
			]) {
				for (const spend of [htlc.success, htlc.timeout]) {
					expect(commits(htlc.output, htlc.internalKey, spend)).to.equal(true);
				}
				// The key path tweak is over the root that includes the leaf.
				const tweaked = ecc.xOnlyPointAddTweak(
					htlc.internalKey,
					tapTweakHash(htlc.internalKey, htlc.merkleRoot)
				)!;
				expect(
					Buffer.from(tweaked.xOnlyPubkey).equals(outputKeyOf(htlc.output))
				).to.equal(true);
			}

			const second = buildTaprootSecondLevelOutput(
				key(1),
				key(2),
				144,
				undefined,
				leaf
			);
			expect(commits(second.output, key(1).subarray(1), second.delay)).to.equal(
				true
			);
			expect(
				second.merkleRoot.equals(
					buildTaprootSecondLevelOutput(key(1), key(2), 144).merkleRoot
				)
			).to.equal(false);
		});

		it('refuses a leaf that is not a tapscript leaf', () => {
			const build = (bad: ITaprootAuxLeaf): Buffer =>
				buildTaprootToRemoteOutput(key(3), undefined, bad).output;
			expect(() => build({ script: leaf.script, leafVersion: 0xc1 })).to.throw(
				'Invalid auxiliary Taproot leaf'
			);
			expect(() => build({ script: leaf.script, leafVersion: 256 })).to.throw(
				'Invalid auxiliary Taproot leaf'
			);
			expect(() => build({ script: Buffer.alloc(10001) })).to.throw(
				'Invalid auxiliary Taproot leaf'
			);
			expect(() => build({ script: 'aa' as unknown as Buffer })).to.throw(
				'Invalid auxiliary Taproot leaf'
			);
			// An even version other than tapscript is a valid leaf.
			expect(() => build({ script: leaf.script, leafVersion: 0xc2 }))
				.to.not //
				.throw();
		});

		it('tweaks the funding key by the asset root, and only when there is one', () => {
			const plain = createTaprootFundingScript(key(6), key(7));
			const rooted = createTaprootFundingScript(
				key(6),
				key(7),
				undefined,
				ASSET_FUNDING_ROOT
			);
			expect(rooted.internalKey).to.deep.equal(plain.internalKey);
			expect(rooted.outputKey.equals(plain.outputKey)).to.equal(false);
			const expected = ecc.xOnlyPointAddTweak(
				plain.internalKey,
				tapTweakHash(plain.internalKey, ASSET_FUNDING_ROOT)
			)!;
			expect(
				Buffer.from(expected.xOnlyPubkey).equals(rooted.outputKey)
			).to.equal(true);
			expect(() =>
				deriveTaprootFundingKey(key(6), key(7), Buffer.alloc(31))
			).to.throw('Funding Taproot merkle root must be 32 bytes');
		});
	});

	describe('an asset channel', () => {
		it('commits each asset balance and asset HTLC to its leaf, the same on both sides', () => {
			const pair = taprootPair(50);
			addAssetHtlc(pair, 0n, 100_000_000n, 75n);
			addAssetHtlc(pair, 1n, 50_000_000n, undefined);
			const { number, point, aliceState, bobState } = bobNextCommitment(pair);

			const signed = buildRemoteCommitment(aliceState, point, number);
			const held = buildLocalCommitment(bobState, point, number);
			expect(signed.result.tx.getId()).to.equal(held.result.tx.getId());

			const view = held.auxiliary!;
			const map = held.result.outputMap;
			// Bob holds nothing yet, so his commitment has no to_local: Alice's
			// 925 ride on his to_remote, the asset HTLC has a leaf and the
			// Bitcoin-only HTLC has none.
			expect(map.toLocal).to.equal(undefined);
			expect(view.outputLeaves.get(map.toRemote!)).to.deep.equal(
				leafFor(`${number}:to_remote:925`)
			);
			const assetIndex = view.htlcOutputIndexes!.get('RECEIVED:0')!;
			const plainIndex = view.htlcOutputIndexes!.get('RECEIVED:1')!;
			expect(view.outputLeaves.get(assetIndex)).to.deep.equal(
				leafFor(`${number}:received_htlc:75`)
			);
			expect(view.outputLeaves.has(plainIndex)).to.equal(false);
			expect([...view.secondLevelLeaves.keys()]).to.deep.equal(['RECEIVED:0']);
			expect(view.outputLeaves.size).to.equal(2);

			// Against the same commitment without asset state: only the two
			// outputs that carry assets changed, and no output moved.
			const ordinary = { ...bobState };
			delete ordinary.auxiliaryState;
			delete ordinary.fundingTaprootMerkleRoot;
			delete ordinary.auxiliaryProvider;
			ordinary.channelType = simpleTaprootType();
			const plain = buildLocalCommitment(ordinary, point, number).result.tx;
			expect(plain.outs.length).to.equal(held.result.tx.outs.length);
			const changed = plain.outs
				.map((out, index) =>
					out.script.equals(held.result.tx.outs[index].script) ? -1 : index
				)
				.filter((index) => index >= 0);
			expect(changed.sort()).to.deep.equal([map.toRemote!, assetIndex].sort());
			plain.outs.forEach((out, index) => {
				expect(out.value).to.equal(held.result.tx.outs[index].value);
			});
		});

		it('signs second-level HTLC transactions the peer verifies, over the asset leaves', () => {
			const pair = taprootPair(52);
			addAssetHtlc(pair, 0n, 100_000_000n, 75n);
			const { number, point, aliceState, bobState } = bobNextCommitment(pair);
			const signatures = signRemoteHtlcSignaturesTaproot(
				aliceState,
				pair.aliceChannel.getSigner()!,
				point,
				number
			);
			expect(signatures.length).to.equal(1);
			expect(
				verifyRemoteHtlcSignaturesTaproot(bobState, point, signatures, number)
			).to.equal(true);

			// A peer whose provider puts another second-level leaf on the HTLC
			// has a different child transaction, and the signature is not for it.
			const build = pair.bobProvider.buildCommitment;
			pair.bobProvider.buildCommitment = (context) => {
				const data = build(context);
				data.secondLevelLeaves.set('RECEIVED:0', leafFor('another child'));
				return data;
			};
			// A provider is asked once about a commitment, so this is a peer
			// that answers so from the start.
			delete bobState.auxiliaryAnswers;
			expect(
				verifyRemoteHtlcSignaturesTaproot(bobState, point, signatures, number)
			).to.equal(false);
		});

		it('refuses to build a commitment the asset side cannot be committed to', () => {
			const { number, point, bobState } = bobNextCommitment(taprootPair(54));
			const build = (change: (pair: IAssetPair) => void): (() => unknown) => {
				const pair = taprootPair(54);
				change(pair);
				const next = bobNextCommitment(pair);
				return () =>
					buildRemoteCommitment(next.aliceState, next.point, next.number);
			};
			expect(number).to.equal(1n);
			expect(point.length).to.equal(33);
			expect(bobState.auxiliaryState!.remoteBalance).to.equal(1000n);

			// An asset HTLC whose Bitcoin carrier would be trimmed as dust.
			expect(build((pair) => addAssetHtlc(pair, 0n, 100_000n, 5n))).to.throw(
				'Asset-bearing HTLC would be trimmed as dust'
			);
			// The same small HTLC with no assets is trimmed as it always was.
			expect(
				build((pair) => addAssetHtlc(pair, 0n, 100_000n, undefined))
			).to.not.throw();

			// A provider that gives an asset balance no leaf.
			expect(
				build((pair) => {
					pair.aliceProvider.buildCommitment = (context) => ({
						customData: Buffer.from(`view:${context.commitmentNumber}`),
						outputLeaves: new Map(),
						secondLevelLeaves: new Map()
					});
				})
			).to.throw('Missing asset balance commitment leaf');

			// A provider that gives an asset HTLC no leaf.
			expect(
				build((pair) => {
					addAssetHtlc(pair, 0n, 100_000_000n, 75n);
					const inner = pair.aliceProvider.buildCommitment;
					pair.aliceProvider.buildCommitment = (context) => {
						const data = inner(context);
						data.secondLevelLeaves.clear();
						return data;
					};
				})
			).to.throw('Missing asset HTLC commitment leaf');

			// A leaf on an anchor, which carries no assets.
			expect(
				build((pair) => {
					const inner = pair.aliceProvider.buildCommitment;
					pair.aliceProvider.buildCommitment = (context) => {
						const data = inner(context);
						const anchor = context.outputs.find((output) =>
							output.role.startsWith('anchor_')
						)!;
						data.outputLeaves.set(anchor.outputIndex, leafFor('anchor'));
						return data;
					};
				})
			).to.throw('Invalid asset auxiliary output index');

			// An asset balance below zero.
			expect(
				build((pair) => {
					writableState(pair.aliceChannel).auxiliaryState!.localBalance = -1n;
				})
			).to.throw('Negative asset commitment balance');

			// Asset state with no provider attached.
			expect(
				build((pair) => {
					delete writableState(pair.aliceChannel).auxiliaryProvider;
				})
			).to.throw('Asset channel state or auxiliary provider is unavailable');
		});

		it('carries the provider signatures in commitment_signed and keeps both views', () => {
			const pair = taprootPair(56);
			expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);

			const signed = pair.wire.filter(
				(m) => m.type === MessageType.COMMITMENT_SIGNED
			);
			expect(signed.map((m) => m.from)).to.deep.equal(['alice', 'bob']);
			for (const message of signed) {
				const decoded = decodeCommitmentSignedMessage(message.payload, {
					customRecords: true
				});
				expect([...decoded.customRecords!.keys()]).to.deep.equal([65538n]);
				// A reader that was not told about asset channels refuses it.
				expect(() => decodeCommitmentSignedMessage(message.payload)).to.throw();
			}

			for (const channel of [pair.aliceChannel, pair.bobChannel]) {
				const state = channel.getFullState();
				expect(state.state).to.equal(ChannelState.NORMAL);
				expect(state.localCommitmentNumber).to.equal(1n);
				expect(state.remoteCommitmentNumber).to.equal(1n);
				const auxiliary = state.auxiliaryState!;
				expect([...auxiliary.remoteCommitments.keys()]).to.deep.equal([1n]);
				expect([...auxiliary.localCommitments.keys()]).to.deep.equal([1n]);
				// What the peer signed for our commitment is kept with its view.
				expect([
					...auxiliary.localCommitments.get(1n)!.peerSignatures!.keys()
				]).to.deep.equal([65538n]);
				expect([...state.lastSentAuxiliaryRecords!.keys()]).to.deep.equal([
					65538n
				]);
			}
			// Each side holds, as its local view, the view the other signed.
			expect(
				pair.bobChannel.getFullState().auxiliaryState!.localCommitments.get(1n)!
					.outputLeaves
			).to.deep.equal(
				pair.aliceChannel
					.getFullState()
					.auxiliaryState!.remoteCommitments.get(1n)!.outputLeaves
			);

			// Later rounds keep, on each side, the views of the two commitments
			// that can still be broadcast: the current one and the one before
			// it until that is revoked.
			expect(pair.alice.updateChannelFee(pair.id, 800).ok).to.equal(true);
			expect(pair.alice.updateChannelFee(pair.id, 900).ok).to.equal(true);
			const bob = pair.bobChannel.getFullState().auxiliaryState!;
			expect([...bob.localCommitments.keys()]).to.deep.equal([2n, 3n]);
			expect([...bob.remoteCommitments.keys()]).to.deep.equal([2n, 3n]);
		});

		it('fails the channel on an invalid asset signature before revoking', () => {
			const pair = taprootPair(58);
			pair.bobProvider.verifyHtlcs = (): boolean => false;
			const before = pair.bobChannel.getFullState().localCommitmentNumber;
			pair.alice.updateChannelFee(pair.id, 700);

			const bob = pair.bobChannel.getFullState();
			expect(bob.localCommitmentNumber).to.equal(before);
			expect(bob.auxiliaryState!.localCommitments.has(1n)).to.equal(false);
			expect(
				pair.wire.some(
					(m) => m.from === 'bob' && m.type === MessageType.REVOKE_AND_ACK
				)
			).to.equal(false);
			const error = pair.wire.find(
				(m) => m.from === 'bob' && m.type === MessageType.ERROR
			);
			expect(error, 'Bob tells the peer why').to.not.equal(undefined);
			expect(error!.payload.toString('latin1')).to.include(
				'Invalid asset HTLC signature'
			);
		});

		it('fails the channel when the asset signature is missing or altered on the wire', () => {
			for (const [seed, rewrite] of [
				[60, (): Map<bigint, Buffer> | undefined => undefined],
				[
					62,
					(): Map<bigint, Buffer> => new Map([[65538n, Buffer.alloc(32, 9)]])
				]
			] as const) {
				const pair = taprootPair(seed);
				pair.intercept.fn = (from, type, payload): Buffer => {
					if (from !== 'alice' || type !== MessageType.COMMITMENT_SIGNED) {
						return payload;
					}
					const message = decodeCommitmentSignedMessage(payload, {
						customRecords: true
					});
					const { customRecords: _dropped, ...rest } = message;
					const records = rewrite();
					return encodeCommitmentSignedMessage({
						...rest,
						...(records ? { customRecords: records } : {})
					});
				};
				pair.alice.updateChannelFee(pair.id, 700);
				expect(pair.bobChannel.getFullState().localCommitmentNumber).to.equal(
					0n
				);
				expect(
					pair.wire.some(
						(m) => m.from === 'bob' && m.type === MessageType.REVOKE_AND_ACK
					)
				).to.equal(false);
			}
		});

		it('does not sign a round its provider cannot sign, and writes nothing', () => {
			const pair = taprootPair(64);
			pair.aliceProvider.signHtlcs = (): never => {
				throw new Error('asset signer offline');
			};
			const before = JSON.stringify(
				serializeChannelState(pair.aliceChannel.getFullState())
			);
			pair.alice.updateChannelFee(pair.id, 700);
			expect(
				pair.wire.some((m) => m.type === MessageType.COMMITMENT_SIGNED)
			).to.equal(false);
			const after = pair.aliceChannel.getFullState();
			expect(after.remoteCommitmentNumber).to.equal(0n);
			expect(after).to.not.have.property('lastSentAuxiliaryRecords');
			// The fee update itself is pending; no signature state was written.
			const parsed = JSON.parse(before);
			const now = JSON.parse(JSON.stringify(serializeChannelState(after)));
			expect(now.lastSentCommitmentSigned).to.equal(
				parsed.lastSentCommitmentSigned
			);
			expect(now.lastSentPartialSignatureWithNonce).to.equal(
				parsed.lastSentPartialSignatureWithNonce
			);
		});

		it('rebuilds its signed commitment from the stored view, and its witness spends the rooted funding key', () => {
			const pair = taprootPair(66);
			expect(pair.alice.updateChannelFee(pair.id, 700).ok).to.equal(true);

			// Through storage and back, with the provider attached again.
			const stored = JSON.parse(
				JSON.stringify(serializeChannelState(pair.bobChannel.getFullState()))
			);
			const state = deserializeChannelState(stored);
			state.auxiliaryProvider = pair.bobProvider;
			const point = getPerCommitmentPoint(state.localPerCommitmentSeed, 1n);
			const signedTxid = buildLocalCommitment(
				state,
				point,
				1n,
				true
			).result.tx.getId();

			// The provider now answers differently. An unsigned build follows
			// it; the signed rebuild keeps the leaves the signature covers.
			const inner = pair.bobProvider.buildCommitment;
			pair.bobProvider.buildCommitment = (context) => {
				const data = inner(context);
				for (const index of data.outputLeaves.keys()) {
					data.outputLeaves.set(index, leafFor('a different answer'));
				}
				return data;
			};
			expect(buildLocalCommitment(state, point, 1n).result.tx.getId())
				.to.not //
				.equal(signedTxid);
			expect(
				buildLocalCommitment(state, point, 1n, true).result.tx.getId()
			).to.equal(signedTxid);

			// A stored view that no longer matches the transaction stops the
			// rebuild instead of putting leaves on the wrong outputs.
			state
				.auxiliaryState!.localCommitments.get(1n)!
				.htlcOutputIndexes!.set('RECEIVED:9', 2);
			expect(() => buildLocalCommitment(state, point, 1n, true)).to.throw(
				'Persisted asset commitment does not match the rebuilt transaction'
			);

			// The live channel's own witness for that commitment is a key
			// spend that verifies under the funding key tweaked by the asset
			// root: it is what a force close would publish.
			pair.bobProvider.buildCommitment = inner;
			const live = writableState(pair.bobChannel);
			const plan = pair.bobChannel.prepareForceClose(
				pair.bobChannel.getSigner()!
			);
			if (!plan.ok) throw new Error(plan.error);
			const tx = bitcoin.Transaction.fromBuffer(plan.commitmentTx);
			expect(tx.getId()).to.equal(signedTxid);
			verifyFundingSpend(tx, live);
		});
	});

	describe('commitment_signed custom records', () => {
		const base = {
			channelId: Buffer.alloc(32, 0x31),
			signature: Buffer.alloc(64),
			htlcSignatures: [Buffer.alloc(64, 0x33)],
			partialSignatureWithNonce: Buffer.alloc(98, 0x36)
		};

		it('round trips odd and even custom records for a reader that asks for them', () => {
			const customRecords = new Map([
				[65536n, Buffer.from('asset')],
				[65538n, Buffer.from('signature')],
				[65543n, Buffer.from('future')]
			]);
			const payload = encodeCommitmentSignedMessage({ ...base, customRecords });
			const decoded = decodeCommitmentSignedMessage(payload, {
				customRecords: true
			});
			expect(decoded.customRecords).to.deep.equal(customRecords);
			expect(decoded.partialSignatureWithNonce).to.deep.equal(
				base.partialSignatureWithNonce
			);
			// The standard fields come first: the standard prefix is unchanged.
			const plain = encodeCommitmentSignedMessage(base);
			expect(payload.subarray(0, plain.length).equals(plain)).to.equal(true);
		});

		it('is read by default as it always was', () => {
			const even = encodeCommitmentSignedMessage({
				...base,
				customRecords: new Map([[65538n, Buffer.from('signature')]])
			});
			expect(() => decodeCommitmentSignedMessage(even)).to.throw();
			// An odd unknown record is skipped and not surfaced.
			const odd = encodeCommitmentSignedMessage({
				...base,
				customRecords: new Map([[65543n, Buffer.from('future')]])
			});
			expect(decodeCommitmentSignedMessage(odd)).to.not.have.property(
				'customRecords'
			);
			expect(
				decodeCommitmentSignedMessage(encodeCommitmentSignedMessage(base), {
					customRecords: true
				})
			).to.not.have.property('customRecords');
		});

		it('refuses to encode reserved, malformed and oversized custom records', () => {
			expect(() =>
				encodeCommitmentSignedMessage({
					...base,
					customRecords: new Map([[2n, Buffer.alloc(98)]])
				})
			).to.throw('Invalid or reserved Lightning custom record');
			expect(() =>
				encodeCommitmentSignedMessage({
					...base,
					customRecords: new Map([[65538n, Buffer.alloc(65533)]])
				})
			).to.throw('payload');
		});
	});
});
