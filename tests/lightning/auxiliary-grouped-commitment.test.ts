import { expect } from 'chai';
import type { IAuxiliarySigningContext } from '../../src/lightning/channel/auxiliary';
import type { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	isFixedAssetHtlcChannel,
	isRevokedChildCustodyChannel
} from '../../src/lightning/channel/types';
import { encodeBigSize } from '../../src/lightning/message/codec';
import { MAX_LIGHTNING_PAYLOAD } from '../../src/lightning/message/custom-records';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { MessageType } from '../../src/lightning/message/types';
import { Feature } from '../../src/lightning/features/flags';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { onPersist } from './helpers/channel-persistence';
import {
	hash,
	taprootPair,
	overlayChannelType,
	amountRecord
} from './helpers/auxiliary-pair';
import { issuances } from './helpers/grouped-asset-fixture';
import { writableState } from './helpers/writable-state';

function encodeList(values: Buffer[]): Buffer {
	return Buffer.concat([
		encodeBigSize(BigInt(values.length)),
		...values.flatMap((value) => [encodeBigSize(BigInt(value.length)), value])
	]);
}

/** Synthetic signatures identify the transaction, ordered output and issuance. */
function signatureRecord({ commitment }: IAuxiliarySigningContext): Buffer {
	const { tx, outputMap } = commitment.result;
	const txHash = tx.getHash();
	return encodeList(
		outputMap.htlcs.map((index) => {
			const output = tx.outs[index];
			const position = Buffer.alloc(4);
			position.writeUInt32BE(index);
			const signatures = issuances.map(({ id }) => {
				const digest = hash(
					Buffer.concat([txHash, position, output.script, id])
				);
				return encodeTlvStream([
					{ type: 0n, value: id },
					{ type: 1n, value: Buffer.concat([digest, hash(digest)]) },
					{ type: 2n, value: Buffer.from([0, 0, 0, 0x83]) }
				]);
			});
			return encodeTlvStream([{ type: 0n, value: encodeList(signatures) }]);
		})
	);
}

/** Stage a committed set in both snapshots before requesting the next signed round. */
function fillBothDirections(channel: Channel, alice: boolean): void {
	const state = writableState(channel);
	const wireAmount = 354_000n;
	for (const offered of [true, false]) {
		for (let i = 0; i < 83; i++) {
			const id = BigInt(i);
			const sender = offered === alice ? 'alice' : 'bob';
			const amount = BigInt((i % 3) + 3);
			state.htlcs.set(`${offered ? 'offered' : 'received'}-${id}`, {
				id,
				amountMsat: wireAmount,
				paymentHash: hash(`${sender} group payment ${id}`),
				cltvExpiry: 3000 + i,
				onionRoutingPacket: Buffer.alloc(1366),
				state: HtlcState.COMMITTED,
				direction: offered ? HtlcDirection.OFFERED : HtlcDirection.RECEIVED,
				customRecords: amountRecord(amount),
				auxiliaryAmount: amount
			});
			if (offered) {
				state.localBalanceMsat -= wireAmount;
				state.auxiliaryState!.localBalance -= amount;
			} else {
				state.remoteBalanceMsat -= wireAmount;
				state.auxiliaryState!.remoteBalance -= amount;
			}
		}
	}
	state.localHtlcCounter = 83n;
}

describe('commitment_signed for three issuances with 83 HTLCs each way', function () {
	this.timeout(120_000);

	for (const custody of [false, true]) {
		const mode = custody
			? 'fixed outputs with child custody'
			: 'taproot overlay';
		it(`stores, replays and verifies the complete signed payload for ${mode}`, () => {
			const channelType = custody
				? overlayChannelType(
						Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS,
						Feature.OPTION_ASSET_CHILD_CUSTODY
				  )
				: overlayChannelType();
			const pair = taprootPair(custody ? 140 : 142, {
				channelType,
				pushMsat: 500_000_000n,
				maxHtlcs: 83
			});
			const { id, aliceChannel: left, bobChannel: right } = pair;
			const aliceStore = new MemoryStorage();
			const bobStore = new MemoryStorage();
			for (const [manager, store] of [
				[pair.alice, aliceStore],
				[pair.bob, bobStore]
			] as const) {
				onPersist(manager, ({ channel, peerPubkey, channelId }) => {
					store.saveChannel(
						channelId.toString('hex'),
						channel.getFullState(),
						peerPubkey
					);
				});
			}
			const sent = new Map<string, Buffer>();
			const verified = new Map<string, Buffer>();
			const sender = pair.aliceProvider;
			const receiver = pair.bobProvider;
			for (const provider of [sender, receiver]) {
				provider.signHtlcs = (context): Map<bigint, Buffer> => {
					const record = signatureRecord(context);
					if (provider === sender)
						sent.set(context.commitment.result.tx.getId(), record);
					return new Map([[65537n, record]]);
				};
				provider.verifyHtlcs = (context, records): boolean => {
					const record = signatureRecord(context);
					if (!records.get(65537n)?.equals(record)) return false;
					if (provider === receiver)
						verified.set(context.commitment.result.tx.getId(), record);
					return true;
				};
			}
			for (const channel of [left, right]) {
				const state = channel.getFullState();
				expect(state.localConfig.maxAcceptedHtlcs).to.equal(83);
				expect(state.remoteConfig.maxAcceptedHtlcs).to.equal(83);
				expect(isRevokedChildCustodyChannel(state.channelType)).to.equal(
					custody
				);
				expect(isFixedAssetHtlcChannel(state.channelType)).to.equal(custody);
			}
			for (const channel of [left, right]) {
				const aux = writableState(channel).auxiliaryState!;
				aux.localBalance = 900n;
				aux.remoteBalance = 900n;
			}
			fillBothDirections(left, true);
			fillBothDirections(right, false);
			const captured: Buffer[] = [];
			pair.intercept.fn = (from, type, payload): Buffer | null => {
				if (from === 'alice' && type === MessageType.COMMITMENT_SIGNED) {
					captured.push(Buffer.from(payload));
					if (captured.length === 1) return null;
				}
				return payload;
			};
			const initial = right.getFullState().localCommitmentNumber;
			const changed = pair.alice.updateChannelFee(id, 700);
			expect(changed.ok, JSON.stringify(pair.errors)).to.equal(true);
			expect(captured, pair.errors.join(' ')).to.have.length(1);
			expect(sent.size).to.equal(1);
			const [[txid, record]] = sent;
			const msg = decodeCommitmentSignedMessage(captured[0], {
				customRecords: true
			});
			expect(msg.htlcSignatures).to.have.length(166);
			expect(msg.htlcSignatures.every((sig) => sig.length === 64)).to.equal(
				true
			);
			expect(msg.partialSignatureWithNonce).to.have.length(98);
			expect(record.length).to.equal(54615);
			expect(msg.customRecords!.get(65537n)).to.deep.equal(record);
			expect([...msg.customRecords!.keys()]).to.deep.equal(
				custody ? [65537n, 65553n] : [65537n]
			);
			expect(captured[0].length).to.equal(custody ? 65517 : 65445);
			expect(captured[0].length).to.be.at.most(MAX_LIGHTNING_PAYLOAD);
			const durable = aliceStore.loadChannel(id.toString('hex'))!.state;
			expect(durable.lastSentAuxiliaryRecords).to.deep.equal(msg.customRecords);
			expect(durable.lastSentHtlcSignatures).to.deep.equal(msg.htlcSignatures);
			expect(durable.lastSentPartialSignatureWithNonce).to.deep.equal(
				msg.partialSignatureWithNonce
			);
			expect(right.getFullState().localCommitmentNumber).to.equal(initial);
			pair.alice.handlePeerDisconnected(pair.bobPubkey);
			pair.bob.handlePeerDisconnected(pair.alicePubkey);
			const reestablish: Array<() => void> = [];
			const observe = pair.intercept.fn;
			pair.intercept.fn = (from, type, payload): Buffer | null => {
				expect(type).to.equal(MessageType.CHANNEL_REESTABLISH);
				reestablish.push(() => {
					if (from === 'alice')
						pair.bob.handleMessage(pair.alicePubkey, type, payload);
					else pair.alice.handleMessage(pair.bobPubkey, type, payload);
				});
				return null;
			};
			pair.alice.handlePeerReconnected(pair.bobPubkey);
			pair.bob.handlePeerReconnected(pair.alicePubkey);
			expect(reestablish).to.have.length(2);
			pair.intercept.fn = observe;
			for (const deliver of reestablish) deliver();
			expect(captured.length, pair.errors.join(' ')).to.be.at.least(2);
			expect(captured[1]).to.deep.equal(captured[0]);
			expect(verified.get(txid)).to.deep.equal(record);
			const accepted = bobStore.loadChannel(id.toString('hex'))!.state;
			expect(accepted.localCommitmentNumber).to.equal(initial + 1n);
			const local = accepted.auxiliaryState!.localCommitments.get(
				initial + 1n
			)!;
			const remote = durable.auxiliaryState!.remoteCommitments.get(
				initial + 1n
			)!;
			expect(local.peerSignatures).to.deep.equal(msg.customRecords);
			expect(local.customData).to.deep.equal(remote.customData);
			expect(local.outputLeaves).to.deep.equal(remote.outputLeaves);
			expect(local.htlcOutputIndexes!.size).to.equal(166);
			expect(remote.htlcOutputIndexes!.size).to.equal(166);
			for (const [key, index] of remote.htlcOutputIndexes!) {
				const [direction, htlcId] = key.split(':');
				const otherDirection =
					direction === HtlcDirection.OFFERED
						? HtlcDirection.RECEIVED
						: HtlcDirection.OFFERED;
				const otherKey = `${otherDirection}:${htlcId}`;
				expect(local.htlcOutputIndexes!.get(otherKey)).to.equal(index);
				expect(local.secondLevelLeaves.get(otherKey)).to.deep.equal(
					remote.secondLevelLeaves.get(key)
				);
			}
			if (custody) {
				const child = msg.customRecords!.get(65553n)!;
				expect(child).to.have.length(66);
				expect(child[0]).to.equal(1);
				expect(child.subarray(1, 33).toString('hex')).to.equal(txid);
				expect(local.secondLevelCommitmentTxid).to.equal(txid);
				expect(child.subarray(33)).to.deep.equal(
					local.secondLevelRevocationBasepoint
				);
			}
			expect(left.getState()).to.equal(ChannelState.NORMAL);
			expect(right.getState()).to.equal(ChannelState.NORMAL);
		});
	}
});
