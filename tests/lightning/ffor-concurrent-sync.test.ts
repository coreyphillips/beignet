import { expect } from 'chai';
import { decodeFforSyncReplyMessage } from '../../src/lightning/ffor/messages';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelPersistEvent } from '../../src/lightning/channel/channel-actions';
import {
	activate,
	AMOUNTS,
	balances,
	createPair,
	expectHealthy,
	expectVouchersCarried,
	pay,
	record,
	restart,
	vouchers
} from './helpers/ffor-concurrent-pair';

describe('FFOR nonterminal receipt synchronization', function () {
	this.timeout(30_000);
	for (const version of [1, 2] as const) {
		it(`waits for version ${version} voucher removal before reporting a live redemption`, () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true, version);
			pair.link.holdAt = (from, type) =>
				from === 'S' && type === MessageType.COMMITMENT_SIGNED;
			expect(
				pair.rManager.fforAddPreimage(
					pair.channelId,
					record(pair.sChannel).preimages[0]
				).ok
			).to.be.true;
			expect(record(pair.sChannel).slotRedeemed?.[0]).to.be.true;
			expect(record(pair.sChannel).voucherOutcomes?.[0]).to.equal(undefined);
			expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
			expect(
				decodeFforSyncReplyMessage(
					record(pair.sChannel).syncSnapshotWire!.subarray(2)
				).preimages
			).to.have.length(0);
			pair.link.holdAt = null;
			pair.link.release('S');
			expect(record(pair.sChannel).voucherOutcomes?.[0]?.outcome).to.equal(
				'fulfilled'
			);
			expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
			expect(
				decodeFforSyncReplyMessage(
					record(pair.rChannel).syncSnapshotWire!.subarray(2)
				).preimages.map((p) => p.k)
			).to.deep.equal([1]);
			expectHealthy(pair);
		});

		it(`keeps version ${version} active with stable empty and growing snapshots`, () => {
			const pair = createPair({ pushSat: 200_000n });
			activate(pair, AMOUNTS, true, version);
			const fetch = (): ReturnType<typeof decodeFforSyncReplyMessage> => {
				expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
				return decodeFforSyncReplyMessage(
					record(pair.rChannel).syncSnapshotWire!.subarray(2)
				);
			};
			expect(fetch().snapshotSeq).to.equal(0n);
			const firstNonce = fetch().nonce;
			expect(record(pair.rChannel).syncRequestWire).to.equal(undefined);
			pair.sManager.fforSetSlot(
				pair.channelId,
				1,
				FforSlotState.SETTLING,
				'upstream:1'
			);
			expect(fetch().preimages).to.have.length(0);
			pair.sManager.fforSetSlot(
				pair.channelId,
				1,
				FforSlotState.SETTLED,
				'upstream:1'
			);
			const settled = fetch();
			expect(settled.snapshotSeq).to.equal(1n);
			expect(settled.preimages.map((p) => p.k)).to.deep.equal([1]);
			expect(settled.nonce.equals(firstNonce)).to.be.false;
			expect(fetch().snapshotSeq).to.equal(1n);
			expect(record(pair.sChannel).slotRedeemed?.[0]).to.be.true;
			expect(record(pair.rChannel).voucherOutcomes?.[0]?.outcome).to.equal(
				'fulfilled'
			);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
			expectVouchersCarried(pair, [2, 3]);
			pay(pair, 'R', 1_000_000n);
			expectHealthy(pair);
		});

		it(`redeems version ${version} payer proof without closing other slots`, () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true, version);
			const before = balances(pair);
			const proof = record(pair.sChannel).preimages[1];
			expect(pair.rManager.fforAddPreimage(pair.channelId, proof).ok).to.be
				.true;
			expect(balances(pair).r).to.equal(before.r + AMOUNTS[1]);
			expect(record(pair.sChannel).slotRedeemed?.[1]).to.be.true;
			expect(record(pair.sChannel).slotStates[1]).to.equal(
				FforSlotState.UNUSED
			);
			expect(pair.sChannel.fforSettlementRefusal(2, 200)).to.equal(
				'voucher already redeemed'
			);
			expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
			expect(
				decodeFforSyncReplyMessage(
					record(pair.rChannel).syncSnapshotWire!.subarray(2)
				).preimages.map((p) => p.k)
			).to.deep.equal([2]);
			expectVouchersCarried(pair, [1, 3]);
			expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
			expectHealthy(pair);
		});

		it(`closes a fully redeemed version ${version} book without another payment round`, () => {
			const pair = createPair();
			activate(pair, AMOUNTS, true, version);
			for (const proof of record(pair.sChannel).preimages) {
				expect(pair.rManager.fforAddPreimage(pair.channelId, proof).ok).to.be
					.true;
			}
			expect(vouchers(pair.rChannel)).to.have.length(0);
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
			expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
			expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
			expectHealthy(pair);
		});
	}

	it('persists one outstanding nonce and replays it after receiver restart', () => {
		const pair = createPair();
		activate(pair, AMOUNTS, true, 2);
		pair.link.drop = (_, type): boolean => type === MessageType.FF_SYNC_REPLY;
		expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
		const wire = Buffer.from(record(pair.rChannel).syncRequestWire!);
		expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
		expect(record(pair.rChannel).syncRequestWire!.equals(wire)).to.be.true;
		pair.link.disconnect();
		restart(pair, 'R');
		expect(record(pair.rChannel).syncRequestWire!.equals(wire)).to.be.true;
		pair.link.drop = null;
		pair.link.reconnect();
		expect(record(pair.rChannel).syncRequestWire).to.equal(undefined);
		expect(record(pair.rChannel).syncSnapshotWire).to.not.equal(undefined);
		expect(
			pair.link.log
				.filter((m) => m.type === MessageType.FF_SYNC)
				.every((m) => m.payload.equals(wire.subarray(2)))
		).to.be.true;
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expectHealthy(pair);
	});

	it('retains the sender sequence and receipt content across restart', () => {
		const pair = createPair();
		activate(pair, AMOUNTS, true, 2);
		expect(
			pair.rManager.fforAddPreimage(
				pair.channelId,
				record(pair.sChannel).preimages[0]
			).ok
		).to.be.true;
		expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
		const before = decodeFforSyncReplyMessage(
			record(pair.sChannel).syncSnapshotWire!.subarray(2)
		);
		pair.link.disconnect();
		restart(pair, 'S');
		pair.link.reconnect();
		expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
		const after = decodeFforSyncReplyMessage(
			record(pair.sChannel).syncSnapshotWire!.subarray(2)
		);
		expect(after.snapshotSeq).to.equal(before.snapshotSeq);
		expect(after.settled).to.deep.equal(before.settled);
		expect(after.preimages).to.deep.equal(before.preimages);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expectHealthy(pair);
	});

	it('persists a snapshot before its reply and releases it only after the quorum barrier', async () => {
		const pair = createPair();
		activate(pair, AMOUNTS, true, 2);
		let release!: (value: { released: boolean; reason: string }) => void;
		let durable = false;
		const wait = new Promise<{ released: boolean; reason: string }>(
			(resolve) => {
				release = resolve;
			}
		);
		pair.sConfig.durabilityBarrier = {
			enforcing: true,
			isReleased: (sequence): boolean => durable && sequence === 7n,
			whenReleased: (
				sequence
			): Promise<{ released: boolean; reason: string }> => {
				expect(sequence).to.equal(7n);
				return wait;
			}
		};
		let persisted: Buffer | undefined;
		pair.sManager.on('channel:persist', ({ request }: IChannelPersistEvent) => {
			if (!request) return;
			persisted = Buffer.from(record(pair.sChannel).syncSnapshotWire!);
			request.committed = true;
			request.frameSequence = 7n;
			request.outboxIds = request.outbound.map((_, i) => i + 1);
		});
		expect(pair.rManager.fforSync(pair.channelId).ok).to.be.true;
		expect(persisted).not.to.equal(undefined);
		expect(
			pair.link.log.filter((m) => m.type === MessageType.FF_SYNC_REPLY)
		).to.have.length(0);
		expect(record(pair.rChannel).syncRequestWire).not.to.equal(undefined);
		durable = true;
		release({ released: true, reason: 'durable' });
		await new Promise<void>((resolve) => setImmediate(resolve));
		expect(
			pair.link.log
				.filter((m) => m.type === MessageType.FF_SYNC_REPLY)
				.map((m) => m.payload)
		).to.deep.equal([persisted!.subarray(2)]);
		expect(record(pair.rChannel).syncRequestWire).to.equal(undefined);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expectHealthy(pair);
	});
});
