/**
 * M9.1 (spec section 9.6.5, section 15.3): store before you propagate, on a
 * four-node world P -> W -> S -> R with R offline. The witness W records
 * the delegated preimage durably before its upstream update_fulfill_htlc
 * leaves; the payer sees success; S sends nothing to R; a store that
 * refuses holds the fulfil until the bounded deadline (wall clock, or the
 * incoming HTLC's expiry less the safety delta) and the record that lands
 * afterwards carries `unbarriered`; a replayed downstream fulfil makes no
 * second record; and R, back online, fetches the record and claims the
 * voucher on-chain with no S (M9.2 in process).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { PaymentStatus } from '../../src/lightning/node/types';
import { MessageType } from '../../src/lightning/message/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { FforSlotState } from '../../src/lightning/ffor/types';
import {
	CommitmentType,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { activate, forceCloseAndObserve, record } from './helpers/ffor-world';
import {
	IWitnessWorld,
	createWitnessWorld,
	fulfilsToP,
	sleep,
	waitFor
} from './helpers/ffor-witness-world';

/** Make W's record store refuse until healed. */
function failingRecordStore(w: IWitnessWorld): {
	heal: () => void;
	failures: () => number;
} {
	let failing = true;
	let failures = 0;
	const original = w.wStorage.saveMetadata.bind(w.wStorage);
	w.wStorage.saveMetadata = (key: string, value: string): void => {
		if (failing && key.startsWith('ffor_witness_record')) {
			failures++;
			throw new Error('disk full');
		}
		original(key, value);
	};
	return {
		heal: (): void => void (failing = false),
		failures: (): number => failures
	};
}

async function setup(
	w: IWitnessWorld
): Promise<{ bolt11: string; paymentHash: Buffer }> {
	activate(w, { witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')] });
	await w.r.provisionFforWitness(w.srHex, w.w.getNodeId());
	const bolt11 = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
	w.sr.disconnect();
	for (const l of [w.pw, w.ws, w.sr]) l.log.length = 0;
	return { bolt11, paymentHash: decodeInvoice(bolt11).paymentHash };
}

describe('FFOR receipt witness: store before propagate (M9.1)', function () {
	this.timeout(60_000);

	it('the record is on disk before the upstream fulfil leaves; the payer succeeds; S sends R nothing; R fetches and claims', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		let fulfilsAtRecord = -1;
		let rowsAtRecord = -1;
		w.w.on('ffor:witness-recorded', () => {
			fulfilsAtRecord = fulfilsToP(w);
			rowsAtRecord = w.w
				.getFforWitnessService()!
				.ledger.listRecords(
					record(w.r, w.srHex).witnesses[0].mailboxId.toString('hex')
				).length;
		});
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the payer to complete'
		);
		expect(
			fulfilsAtRecord,
			'nothing had gone upstream when the record landed'
		).to.equal(0);
		expect(rowsAtRecord, 'the row was durable at that moment').to.equal(1);
		expect(fulfilsToP(w), 'exactly one upstream fulfil afterwards').to.equal(1);
		expect(w.sr.log, 'S sent R nothing').to.have.length(0);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
		const mailboxIdHex = record(w.r, w.srHex).witnesses[0].mailboxId.toString(
			'hex'
		);
		const rows = w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex);
		expect(rows).to.have.length(1);
		expect(rows[0].unbarriered).to.equal(false);

		// R returns: only W answers. The record verifies and credits t_1.
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched[0].ok).to.be.true;
		expect(fetched[0].records).to.deep.equal([
			{ k: 1, unbarriered: false, verified: true }
		]);
		expect(fetched[0].credited).to.equal(1);
		const t1 = record(w.s, w.srHex).preimages[0];
		expect(record(w.r, w.srHex).knownPreimages[0]!.equals(t1)).to.be.true;
		// And the voucher claims on R's own commitment with no S (M9.2).
		const view = forceCloseAndObserve(
			w,
			w.r,
			w.rConfig.fundingPrivkey!,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		expect(view.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		const voucher = view.outputs.find(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC &&
				o.paymentHash?.equals(paymentHash)
		);
		expect(voucher?.status).to.equal(OutputStatus.SPEND_BROADCAST);
		w.wStorage.close();
	});

	it('a store that refuses holds the fulfil until the wall-clock deadline, then the late record is unbarriered', async () => {
		const w = createWitnessWorld({ barrierMs: 1000 });
		const { bolt11, paymentHash } = await setup(w);
		const store = failingRecordStore(w);
		const released: string[] = [];
		w.w.on('ffor:witness-released', (e: { reason: string }) =>
			released.push(e.reason)
		);
		w.p.sendPayment(bolt11);
		expect(store.failures()).to.be.greaterThan(0);
		expect(fulfilsToP(w), 'held: nothing upstream yet').to.equal(0);
		expect(w.p.getPayment(paymentHash)?.status).to.equal(PaymentStatus.PENDING);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the deadline to propagate'
		);
		expect(released).to.deep.equal(['deadline']);
		expect(fulfilsToP(w)).to.equal(1);
		const mailboxIdHex = record(w.r, w.srHex).witnesses[0].mailboxId.toString(
			'hex'
		);
		expect(
			w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex)
		).to.have.length(0);
		// The disk comes back: the retry lands the record, flagged.
		store.heal();
		await waitFor(
			() =>
				w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex).length ===
				1,
			'the late record',
			5_000
		);
		const [row] = w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex);
		expect(row.unbarriered).to.equal(true);
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(fetched[0].records).to.deep.equal([
			{ k: 1, unbarriered: true, verified: true }
		]);
		expect(fetched[0].credited).to.equal(1);
		w.wStorage.close();
	});

	it('the CLTV arm: the incoming expiry less the safety delta propagates a held fulfil, whatever the clock says', async () => {
		// No safetyDelta: the node derives it, one block before its own
		// claim-and-force-close buffer of 18 blocks.
		const w = createWitnessWorld({ barrierMs: 60_000 });
		const { bolt11, paymentHash } = await setup(w);
		failingRecordStore(w);
		w.p.sendPayment(bolt11);
		expect(fulfilsToP(w)).to.equal(0);
		const inbound = w.w
			.getChannelManager()
			.getChannel(w.pwChannelId)!
			.getFullState()
			.htlcs.get('received-0')!;
		w.w.handleNewBlock(inbound.cltvExpiry - 20);
		expect(fulfilsToP(w), 'one block early: still held').to.equal(0);
		w.w.handleNewBlock(inbound.cltvExpiry - 19);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the CLTV deadline to propagate'
		);
		expect(fulfilsToP(w)).to.equal(1);
		w.wStorage.close();
	});

	it('a replayed downstream fulfil creates no second record', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'completion'
		);
		const service = w.w.getFforWitnessService()!;
		const mailboxIdHex = record(w.r, w.srHex).witnesses[0].mailboxId.toString(
			'hex'
		);
		const [row] = service.ledger.listRecords(mailboxIdHex);
		const again = service.interceptDownstreamFulfil({
			outKey: row.outKey,
			preimage: record(w.s, w.srHex).preimages[0],
			paymentHash,
			amountInMsat: 0n,
			amountOutMsat: 0n,
			outgoingCltv: 0,
			incomingCltvExpiry: 0
		});
		expect(again).to.equal('recorded');
		expect(service.ledger.listRecords(mailboxIdHex)).to.have.length(1);
		// A hash in no mailbox is not the witness's business.
		expect(
			service.interceptDownstreamFulfil({
				outKey: 'x:offered-9',
				preimage: crypto.randomBytes(32),
				paymentHash: crypto.randomBytes(32),
				amountInMsat: 0n,
				amountOutMsat: 0n,
				outgoingCltv: 0,
				incomingCltvExpiry: 0
			})
		).to.equal('none');
		w.wStorage.close();
	});

	it('the payer is offline when the downstream fulfil arrives: the owed pass propagates the already-recorded fulfil once', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		// Cut P-W after the add has gone downstream, before S fulfils: the
		// downstream fulfil reaches W while its upstream channel is down.
		w.ws.drop = (from, type): boolean => {
			if (
				from === w.s.getNodeId() &&
				type === MessageType.UPDATE_FULFILL_HTLC
			) {
				w.pw.disconnect();
			}
			return false;
		};
		w.p.sendPayment(bolt11);
		await sleep(50);
		const mailboxIdHex = record(w.r, w.srHex).witnesses[0].mailboxId.toString(
			'hex'
		);
		expect(
			w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex),
			'recorded'
		).to.have.length(1);
		expect(w.p.getPayment(paymentHash)?.status).to.equal(PaymentStatus.PENDING);
		w.pw.reconnect();
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the owed pass to settle upstream'
		);
		expect(
			w.w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex)
		).to.have.length(1);
		w.wStorage.close();
	});
});
