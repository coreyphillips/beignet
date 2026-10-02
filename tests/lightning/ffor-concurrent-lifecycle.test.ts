import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { FforState } from '../../src/lightning/ffor/types';
import {
	funderCommitmentCostSats,
	getCommitmentFeeRate
} from '../../src/lightning/channel/commitment-builder';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import {
	activate,
	balances,
	channel,
	createPair,
	expectHealthy,
	expectVouchersCarried,
	manager,
	offer,
	other,
	pay,
	record,
	restart,
	vouchers
} from './helpers/ffor-concurrent-pair';

const BOOK = [1000000n, 2000000n];

describe('Concurrent receive profile lifecycle qualification', function () {
	this.timeout(60000);
	for (const version of [1, 2] as const) {
		it(`upgrades a completed baseline book to version ${version} after disk restart`, () => {
			const pair = createPair({ pushSat: 200000n });
			activate(pair, BOOK, false);
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
			expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
			const directory = fs.mkdtempSync(
				path.join(os.tmpdir(), 'ffor-profile-upgrade-')
			);
			const file = path.join(directory, 'receiver.sqlite');
			let storage = new SqliteStorage(file);
			try {
				storage.open();
				storage.saveChannel(
					pair.channelId.toString('hex'),
					pair.rChannel.getFullState(),
					pair.sPub
				);
				storage.close();
				storage = new SqliteStorage(file);
				storage.open();
				const saved = storage.loadChannel(pair.channelId.toString('hex'))!;
				restart(pair, 'R', JSON.stringify(serializeChannelState(saved.state)));
				restart(pair, 'S');
				pair.link.reconnect();
				activate(pair, BOOK, true, version);
				pay(pair, 'R', 1000000n);
				pay(pair, 'S', 2000000n);
				expectVouchersCarried(pair, [1, 2]);
				expectHealthy(pair);
			} finally {
				storage.close();
				fs.rmSync(directory, { recursive: true, force: true });
			}
		});
	}

	for (const phase of ['ACTIVE', 'DRAINING'] as const) {
		for (const funder of ['S', 'R'] as const) {
			const makePair = (limits = false): ReturnType<typeof createPair> => {
				const pair = createPair({
					funder,
					pushSat: 300000n,
					...(limits
						? {
								rLocalConfig: {
									maxAcceptedHtlcs: 4,
									maxHtlcValueInFlightMsat: 5000000n
								}
						  }
						: {})
				});
				activate(pair, BOOK, true, 2);
				if (phase === 'DRAINING')
					expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
				expect(record(pair.rChannel).state).to.equal(
					phase === 'ACTIVE' ? FforState.ACTIVE : FforState.DRAINING
				);
				return pair;
			};
			it(`version 2 ${phase}, ${funder} funds: shared count and value limits retain reservations`, () => {
				const pair = makePair(true);
				expect(offer(pair, 'S', 2000001n).result.error).to.equal(
					'Max HTLC value in flight exceeded'
				);
				const first = offer(pair, 'S', 1000000n);
				const second = offer(pair, 'S', 1000000n);
				expect(first.result.ok).to.be.true;
				expect(second.result.ok).to.be.true;
				expect(offer(pair, 'S', 1000n).result.error).to.equal(
					'Max pending HTLCs exceeded'
				);
				expect(
					pair.rManager.fulfillHtlc(pair.channelId, first.id, first.preimage).ok
				).to.be.true;
				expect(offer(pair, 'S', 1000000n).result.ok).to.be.true;
				pay(pair, 'R', 1000000n);
				expectVouchersCarried(pair, [1, 2]);
			});
			for (const sender of ['S', 'R'] as const) {
				it(`version 2 ${phase}, ${funder} funds: ${sender} keeps its reserve and mixed fee buffer`, () => {
					const pair = makePair();
					const from = channel(pair, sender);
					const spendable = from.getSpendableOutboundMsat();
					const state = from.getFullState();
					const reserve = state.remoteConfig.channelReserveSatoshis * 1000n;
					const buffer =
						sender === funder
							? funderCommitmentCostSats(
									getCommitmentFeeRate(state) * 2,
									BOOK.length + 2,
									state.channelType
							  ) * 1000n
							: 0n;
					expect(spendable).to.equal(state.localBalanceMsat - reserve - buffer);
					expect(spendable > 0n).to.be.true;
					expect(from.canOfferHtlcSet([spendable + 1n])).to.be.false;
					expect(offer(pair, sender, spendable + 1n).result.ok).to.be.false;
					const payment = offer(pair, sender, spendable);
					expect(payment.result.ok, payment.result.error).to.be.true;
					expectVouchersCarried(pair, [1, 2]);
					expect(
						manager(pair, other(sender)).fulfillHtlc(
							pair.channelId,
							payment.id,
							payment.preimage
						).ok
					).to.be.true;
					expect(vouchers(pair.rChannel)).to.have.length(2);
				});
			}
			it(`version 2 ${phase}, ${funder} funds: a nonfunder add requires the twice-rate mixed output buffer`, () => {
				const pair = makePair();
				const funded = channel(pair, funder).getFullState();
				const unfunded = channel(pair, other(funder)).getFullState();
				const reserve = funded.remoteConfig.channelReserveSatoshis * 1000n;
				const need =
					funderCommitmentCostSats(
						getCommitmentFeeRate(funded) * 2,
						BOOK.length + 1,
						funded.channelType
					) * 1000n;
				const setHeadroom = (headroom: bigint): void => {
					const delta = funded.localBalanceMsat - reserve - headroom;
					funded.localBalanceMsat -= delta;
					funded.remoteBalanceMsat += delta;
					unfunded.localBalanceMsat += delta;
					unfunded.remoteBalanceMsat -= delta;
				};
				setHeadroom(need - 1000n);
				expect(offer(pair, other(funder), 5000000n).result.ok).to.be.false;
				expect(channel(pair, other(funder)).canOfferHtlcSet([5000000n])).to.be
					.false;
				setHeadroom(need);
				expect(offer(pair, other(funder), 5000000n).result.ok).to.be.true;
				expectVouchersCarried(pair, [1, 2]);
			});
			it(`version 2 ${phase}, ${funder} funds: ordinary dust leaves both voucher outputs intact`, () => {
				const pair = makePair();
				pay(pair, 'S', 100000n);
				pay(pair, 'R', 100000n);
				expectVouchersCarried(pair, [1, 2]);
				expect(
					channel(pair, funder)
						.updateFee(3000)
						.some((action) => action.type === ChannelActionType.ERROR)
				).to.be.true;
				expectHealthy(pair);
			});
		}
	}

	it('version 2 closes after the final voucher while an ordinary HTLC remains pending', () => {
		const pair = createPair({ pushSat: 200000n });
		activate(pair, BOOK, true, 2);
		const ordinary = offer(pair, 'R', 4000000n);
		expect(ordinary.result.ok).to.be.true;
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
		const before = balances(pair).r;
		for (const preimage of record(pair.sChannel).preimages)
			expect(pair.rManager.fforAddPreimage(pair.channelId, preimage).ok).to.be
				.true;
		for (const node of [pair.rChannel, pair.sChannel]) {
			expect(record(node).state).to.equal(FforState.CLOSED);
			expect(vouchers(node)).to.have.length(0);
			expect(node.getFullState().htlcs.size).to.equal(1);
		}
		expect(balances(pair).r).to.equal(before + 3000000n);
		expect(
			pair.sManager.fulfillHtlc(pair.channelId, ordinary.id, ordinary.preimage)
				.ok
		).to.be.true;
		expectHealthy(pair);
	});
});
