import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { OutputType } from '../../src/lightning/chain/types';
import { FforState } from '../../src/lightning/ffor/types';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IPaymentInfo, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	deserializeFforEpoch,
	serializeFforEpoch
} from '../../src/lightning/storage/serialization';
import {
	activate,
	createPair,
	expectHealthy,
	offer,
	record as pairRecord
} from './helpers/ffor-concurrent-pair';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	exposeAndLeave,
	forceCloseAndObserve,
	IWorld,
	pay,
	record,
	TIP
} from './helpers/ffor-world';

describe('FFOR voucher terminal outcomes', function () {
	this.timeout(30_000);
	const nodes: LightningNode[] = [];
	const stores: SqliteStorage[] = [];
	afterEach((): void => {
		for (const node of nodes.splice(0)) node.destroy();
		for (const store of stores.splice(0)) store.close();
	});

	function world(concurrent: boolean): { w: IWorld; storage: SqliteStorage } {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		stores.push(storage);
		const w = createConcurrentWorld({ concurrent, rStorage: storage });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, concurrent);
		return { w, storage };
	}

	it('keeps acknowledged outcome evidence behind a later ordinary signature', () => {
		const pair = createPair({ pushSat: 100_000n });
		activate(pair);
		// Learn proof offline so this case exercises the retirement round.
		pair.link.disconnect();
		expect(
			pair.rManager.fforAddPreimage(
				pair.channelId,
				pairRecord(pair.sChannel).preimages[0]
			).ok
		).to.be.true;
		pair.link.holdAt = (from, type) =>
			from === 'S' && type === MessageType.COMMITMENT_SIGNED;
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
		pair.link.reconnect();
		const acknowledged = pair.rChannel.getFullState().remoteRevocationNumber;
		expect(offer(pair, 'R', 2_000_000n).result.ok).to.be.true;
		expect(pair.rChannel.getFullState().remoteCommitmentNumber).to.equal(
			acknowledged! + 1n
		);
		pair.link.release('S', 1);
		for (const outcome of pairRecord(pair.rChannel).voucherOutcomes!) {
			expect(outcome?.remoteCommitmentNumber).to.equal(acknowledged);
		}
		pair.link.holdAt = null;
		pair.link.release('S');
		expectHealthy(pair);
	});

	for (const concurrent of [false, true]) {
		const profile = concurrent ? 'concurrent' : 'baseline';

		it(`${profile}: records the actual removal only when both views remove the voucher`, () => {
			const pair = createPair({ concurrent });
			activate(pair);
			pair.link.disconnect();
			const preimage = pairRecord(pair.sChannel).preimages[0];
			expect(pair.rManager.fforAddPreimage(pair.channelId, preimage).ok).to.be
				.true;
			pair.link.holdAt = (from, type) =>
				from === 'S' && type === MessageType.COMMITMENT_SIGNED;
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
			pair.link.reconnect();
			expect(pair.rChannel.getFullState().signedLocalRemovals).to.have.length(
				3
			);
			expect(pairRecord(pair.rChannel).voucherOutcomes).to.equal(undefined);
			expect(pairRecord(pair.rChannel).state).to.equal(FforState.DRAINING);
			pair.link.holdAt = null;
			pair.link.release('S');
			const f = pairRecord(pair.rChannel);
			expect(f.state).to.equal(FforState.CLOSED);
			expect(f.voucherOutcomes?.map((o) => o?.outcome)).to.deep.equal([
				'fulfilled',
				'cancelled',
				'cancelled'
			]);
			for (const outcome of f.voucherOutcomes!) {
				expect(outcome?.localCommitmentNumber).to.equal(
					pair.rChannel.getFullState().localCommitmentNumber
				);
				expect(outcome?.remoteCommitmentNumber).to.equal(
					pair.rChannel.getFullState().remoteCommitmentNumber
				);
			}
			const serialized = serializeFforEpoch(f);
			expect(deserializeFforEpoch(serialized).voucherOutcomes).to.deep.equal(
				f.voucherOutcomes
			);
			delete serialized.voucherOutcomes;
			expect(deserializeFforEpoch(serialized).voucherOutcomes).to.equal(
				undefined
			);
		});

		it(`${profile}: late proof custody does not turn a cancelled voucher into a payment`, () => {
			const { w, storage } = world(concurrent);
			const [invoice] = exposeAndLeave(w, [1]);
			expect(invoice).not.to.equal('');
			const hash = record(w.r, w.srHex).paymentHashes[0];
			const preimage = record(w.s, w.srHex).preimages[0];
			const received: IPaymentInfo[] = [];
			w.r.on('payment:received', (p) => received.push(p));
			w.sr.reconnect();
			expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
			expect(record(w.r, w.srHex).voucherOutcomes?.[0]?.outcome).to.equal(
				'cancelled'
			);
			const before = w.r
				.getChannelManager()
				.getChannel(w.srChannelId)!
				.getFullState().localBalanceMsat;
			for (let n = 0; n < 2; n++) {
				expect(w.r.fforAddPreimage(w.srHex, preimage).ok).to.be.true;
				w.r.handleNewBlock(TIP + n + 1);
			}
			expect(storage.loadPreimage(hash.toString('hex'))?.equals(preimage)).to.be
				.true;
			expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
			expect(received).to.have.length(0);
			expect(
				w.r.getChannelManager().getChannel(w.srChannelId)!.getFullState()
					.localBalanceMsat
			).to.equal(before);
			const restored = new LightningNode(w.rConfig);
			nodes.push(restored);
			expect(restored.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
			expect(record(restored, w.srHex).voucherOutcomes?.[0]?.outcome).to.equal(
				'cancelled'
			);
		});

		for (const restart of [false, true]) {
			it(`${profile}: a failed payment write stays pending and retries once after ${
				restart ? 'restart' : 'a block'
			}`, () => {
				const { w, storage } = world(concurrent);
				const [invoice] = exposeAndLeave(w, [1]);
				expect(pay(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
				const hash = record(w.r, w.srHex).paymentHashes[0];
				const savePayment = storage.savePayment.bind(storage);
				let fail = true;
				storage.savePayment = (key, payment): void => {
					if (
						fail &&
						key === hash.toString('hex') &&
						payment.status === PaymentStatus.COMPLETED
					) {
						throw new Error('injected voucher payment write failure');
					}
					savePayment(key, payment);
				};
				const received: IPaymentInfo[] = [];
				w.r.on('payment:received', (p) => received.push(p));
				w.sr.reconnect();
				expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
				expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
				expect(
					storage.loadChannel(w.srHex)?.state.ffor?.voucherOutcomes?.[0]
						?.outcome
				).to.equal('fulfilled');
				expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
				expect(storage.loadPayment(hash.toString('hex'))?.status).to.equal(
					PaymentStatus.PENDING
				);
				expect(received).to.have.length(0);
				fail = false;
				const receiver = restart ? new LightningNode(w.rConfig) : w.r;
				if (restart) nodes.push(receiver);
				receiver.handleNewBlock(TIP + 1);
				expect(receiver.getPayment(hash)?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(storage.loadPayment(hash.toString('hex'))?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				const completedAt = receiver.getPayment(hash)?.completedAt;
				receiver.handleNewBlock(TIP + 2);
				expect(receiver.getPayment(hash)?.completedAt).to.equal(completedAt);
				expect(received).to.have.length(restart ? 0 : 1);
			});
		}

		for (const reorg of [false, true]) {
			it(`${profile}: retries a confirmed claim write${
				reorg
					? ' only after a reorged claim confirms again'
					: ' while the book remains ACTIVE'
			}`, () => {
				const { w, storage } = world(concurrent);
				const [invoice] = exposeAndLeave(w, [1]);
				const paid = pay(w, invoice);
				expect(paid.status).to.equal(PaymentStatus.COMPLETED);
				const hash = record(w.r, w.srHex).paymentHashes[0];
				expect(w.r.fforAddPreimage(w.srHex, paid.preimage!).ok).to.be.true;
				const view = forceCloseAndObserve(
					w,
					w.r,
					w.rConfig.fundingPrivkey,
					w.r,
					w.rConfig.fundingPrivkey
				);
				const voucher = view.outputs.find(
					(o) =>
						o.outputType === OutputType.RECEIVED_HTLC &&
						o.paymentHash?.equals(hash)
				)!;
				const claim = bitcoin.Transaction.fromHex(voucher.sweepTxHex!);
				const savePayment = storage.savePayment.bind(storage);
				let fail = true;
				storage.savePayment = (key, payment): void => {
					if (
						fail &&
						key === hash.toString('hex') &&
						payment.status === PaymentStatus.COMPLETED
					) {
						throw new Error('injected claim payment write failure');
					}
					savePayment(key, payment);
				};
				const received: IPaymentInfo[] = [];
				w.r.on('payment:received', (p) => received.push(p));
				w.r
					.getChannelManager()
					.handleOutputSpent(
						view.tx.getId(),
						voucher.outputIndex,
						claim,
						TIP + 3
					);
				expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
				expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
				expect(received).to.have.length(0);
				fail = false;
				if (reorg) {
					w.r
						.getChannelManager()
						.handleOutputUnspent(view.tx.getId(), voucher.outputIndex);
					w.r.handleNewBlock(TIP + 4);
					expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
					expect(received).to.have.length(0);
					w.r
						.getChannelManager()
						.handleOutputSpent(
							view.tx.getId(),
							voucher.outputIndex,
							claim,
							TIP + 5
						);
				}
				w.r.handleNewBlock(TIP + 6);
				w.r.handleNewBlock(TIP + 7);
				expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
				expect(storage.loadPayment(hash.toString('hex'))?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				expect(w.r.getPayment(hash)?.metadata?.claimTxid).to.equal(
					claim.getId()
				);
				expect(received).to.have.length(1);
			});
		}

		it(`${profile}: a legacy closed row without outcome evidence stays unknown`, () => {
			const { w, storage } = world(concurrent);
			const [invoice] = exposeAndLeave(w, [1]);
			expect(pay(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
			const hash = record(w.r, w.srHex).paymentHashes[0];
			const savePayment = storage.savePayment.bind(storage);
			storage.savePayment = (key, payment): void => {
				if (payment.status === PaymentStatus.COMPLETED)
					throw new Error('injected write failure before upgrade');
				savePayment(key, payment);
			};
			w.sr.reconnect();
			expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
			storage.savePayment = savePayment;
			const old = storage.loadChannel(w.srHex)!;
			delete old.state.ffor!.voucherOutcomes;
			storage.saveChannel(w.srHex, old.state, old.peerPubkey);
			// A pre-archive database has neither embedded outcomes nor custody rows.
			(storage as unknown as { db: { exec(sql: string): void } }).db.exec(
				'DELETE FROM ffor_vouchers'
			);
			const restored = new LightningNode(w.rConfig);
			nodes.push(restored);
			restored.handleNewBlock(TIP + 1);
			expect(record(restored, w.srHex).knownPreimages[0]).not.to.equal(null);
			expect(restored.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		});
	}
});
