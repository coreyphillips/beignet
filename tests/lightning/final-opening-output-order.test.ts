import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Transaction } from 'bitcoinjs-lib';
import { COMMIT_ALL } from './helpers/channel-persistence';
import type { FinalFundingWitnessSigner } from '../../src/lightning/storage/final-opening-funding';
import {
	ChannelManager,
	type IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import {
	deriveV2ChannelId,
	deriveV2TemporaryChannelId
} from '../../src/lightning/channel/validation';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { generateNonce } from '../../src/lightning/crypto/musig';
import {
	decodeAcceptChannel2Message,
	encodeOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import {
	decodeTxCompleteMessage,
	encodeTxAddInputMessage,
	encodeTxAddOutputMessage,
	encodeTxCompleteMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType as M } from '../../src/lightning/message/types';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { alice, bob } from './helpers/final-opening-signing';
import { channelType, inputTransaction } from './helpers/final-opening';

describe('Final opening with editable wallet change', () => {
	it('persists the exact nonce pair for the last candidate when the counterparty adds change after the funding output', async () => {
		const directory = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-open-order-')
		);
		const storage = SqliteStorage.createFinalWallet(
			path.join(directory, 'wallet.db'),
			bob.binding
		);
		try {
			const local = bob.keys;
			const manager = new ChannelManager({
				finalOpening: { storage, root: bob.root },
				finalOpeningNegotiated: (): boolean => true,
				localBasepoints: local.channelBasepoints,
				localPerCommitmentSeed: local.perCommitmentSeed,
				localFundingPrivkey: local.fundingPrivkey,
				channelKeyDeriver: (index): IPerChannelKeys => {
					expect(index).to.equal(bob.index);
					return { ...local, basepoints: local.channelBasepoints };
				},
				allocateChannelKeyIndex: (floor): number =>
					storage.allocateFinalChannelKeyIndex(Math.max(floor, bob.index)),
				verifyRemoteFundingInput: async (): Promise<'unspent'> => 'unspent',
				persistence: COMMIT_ALL
			});
			const unexpected = async (): Promise<never> => {
				throw Error('Unexpected wallet signing during construction');
			};
			manager.setFundingProvider({
				buildFundingTransaction: unexpected,
				broadcastTransaction: unexpected,
				resolveFinalOpeningInputs:
					async (): Promise<FinalFundingWitnessSigner> => (): never => {
						throw Error('Acceptor has no wallet inputs');
					}
			});
			const wire: { type: M; payload: Buffer }[] = [];
			manager.on('message:outbound', (_peer, type, payload) =>
				wire.push({ type, payload })
			);
			manager.on('error', (_id, reason) => {
				throw Error(reason);
			});
			const receive = async (type: M, payload: Buffer): Promise<void> => {
				manager.handleMessage(alice.binding.nodeId, type, payload);
				await new Promise<void>((done) => setImmediate(done));
			};
			const frame = (type: M): Buffer => {
				const m = wire.shift();
				expect(m?.type).to.equal(type);
				return m!.payload;
			};
			const keys = alice.keys.channelBasepoints;
			await receive(
				M.OPEN_CHANNEL2,
				encodeOpenChannel2Message({
					...DEFAULT_CHANNEL_CONFIG,
					...keys,
					channelId: deriveV2TemporaryChannelId(keys.revocationBasepoint),
					channelType: Buffer.from(channelType(80), 'hex'),
					channelFlags: 0,
					fundingSatoshis: 150000n,
					locktime: 0,
					fundingFeeratePerkw: 1000,
					commitmentFeeratePerkw: 1000,
					firstPerCommitmentPoint: Buffer.from(
						alice.points.firstPerCommitmentPoint,
						'hex'
					),
					secondPerCommitmentPoint: getPublicKey(
						generateFromSeed(alice.keys.perCommitmentSeed, MAX_INDEX - 1n)
					)
				})
			);
			const accept = decodeAcceptChannel2Message(frame(M.ACCEPT_CHANNEL2));
			const channelId = deriveV2ChannelId(
					keys.revocationBasepoint,
					accept.revocationBasepoint
				),
				id = channelId.toString('hex');
			const prev = inputTransaction(123, 1000000);
			await receive(
				M.TX_ADD_INPUT,
				encodeTxAddInputMessage({
					channelId,
					serialId: 0n,
					prevTx: prev.toBuffer(),
					prevTxVout: 0,
					sequence: 0xfffffffd
				})
			);
			frame(M.TX_COMPLETE);
			const fundingScript = createTaprootFundingScript(
				keys.fundingPubkey,
				accept.fundingPubkey
			).p2trOutput;
			await receive(
				M.TX_ADD_OUTPUT,
				encodeTxAddOutputMessage({
					channelId,
					serialId: 2n,
					amountSats: 150000n,
					scriptPubkey: fundingScript
				})
			);
			const first = decodeTxCompleteMessage(frame(M.TX_COMPLETE), {
				taproot: true
			}).commitNonces!;
			expect(storage.loadFinalOpening(id)).to.equal(null);
			await receive(
				M.TX_ADD_OUTPUT,
				encodeTxAddOutputMessage({
					channelId,
					serialId: 4n,
					amountSats: 849340n,
					scriptPubkey: prev.outs[0].script
				})
			);
			const final = frame(M.TX_COMPLETE);
			const second = decodeTxCompleteMessage(final, { taproot: true })
				.commitNonces!;
			expect(
				new Set(
					[first.current, first.next, second.current, second.next].map((n) =>
						n.toString('hex')
					)
				).size
			).to.equal(4);
			expect(storage.loadFinalOpening(id)).to.equal(null);
			const remoteNonce = (): Buffer =>
				Buffer.from(generateNonce({ publicKey: keys.fundingPubkey }));
			const remote = encodeTxCompleteMessage({
				channelId,
				commitNonces: { current: remoteNonce(), next: remoteNonce() }
			});
			await receive(M.TX_COMPLETE, remote);
			const candidate = storage.loadFinalOpening(id)!;
			expect(
				Transaction.fromHex(candidate.fundingTxHex).outs.map((o) => o.value)
			).to.deep.equal([150000, 849340]);
			expect(candidate.fundingOutputIndex).to.equal(0);
			expect(storage.loadFinalLocalTxComplete(id)).to.deep.equal(final);
			expect(storage.loadFinalPeerTxComplete(id)).to.deep.equal(remote);
			expect(storage.loadFinalOpeningExit(id)).to.equal(null);
			expect(wire).to.be.empty;
		} finally {
			storage.close();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
