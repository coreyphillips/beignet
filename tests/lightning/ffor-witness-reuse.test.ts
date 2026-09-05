/**
 * M9.4 (spec section 13.7.1): reuse by a witness, characterization. A
 * witness that has recorded t_k can settle a later same-hash HTLC itself
 * and never forward it to S: the second payer sees success, S sees no
 * HTLC, and R's records show one settlement, so the theft is evidence-free
 * at R. This test passes today and is written to INVERT when a
 * payer-bound settlement primitive (section 13.5) makes the second
 * settlement unconstructable.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import {
	NodeLink,
	TIP,
	activate,
	makeNodeConfig,
	openReadyChannel,
	publishChannel,
	record
} from './helpers/ffor-world';

const sleep = (ms: number): Promise<void> =>
	new Promise((r) => setTimeout(r, ms));
async function waitFor(
	cond: () => boolean,
	label: string,
	ms = 5_000
): Promise<void> {
	const deadline = Date.now() + ms;
	while (!cond()) {
		if (Date.now() > deadline) throw new Error(`timed out: ${label}`);
		await sleep(10);
	}
}

describe('FFOR receipt witness reuse characterization (M9.4, section 13.7.1)', function () {
	this.timeout(60_000);

	it('a witness settles a second same-hash HTLC itself, evidence-free at R (inverts when payer-bound settlement lands)', async () => {
		const seed = 7000;
		const p = new LightningNode(makeNodeConfig(seed + 1));
		const p2 = new LightningNode(makeNodeConfig(seed + 5));
		const wStorage = new SqliteStorage(':memory:');
		wStorage.open();
		const w = new LightningNode(
			makeNodeConfig(seed + 4, wStorage, { fforWitness: { enabled: true } })
		);
		const s = new LightningNode(makeNodeConfig(seed + 2));
		const r = new LightningNode(makeNodeConfig(seed + 3));
		for (const n of [p, p2, w, s, r]) n.on('node:error', () => {});
		const pw = new NodeLink(p, w);
		const p2w = new NodeLink(p2, w);
		const ws = new NodeLink(w, s);
		const sr = new NodeLink(s, r);
		new NodeLink(r, w);
		const pwChannelId = openReadyChannel(p, w, 1_000_000n);
		const p2wChannelId = openReadyChannel(p2, w, 1_000_000n);
		const wsChannelId = openReadyChannel(w, s, 1_000_000n);
		const srChannelId = openReadyChannel(s, r, 1_000_000n);
		const scid = (i: number): Buffer =>
			encodeShortChannelId({ block: 500, txIndex: i, outputIndex: 0 });
		publishChannel(p, p, w, pwChannelId, scid(1));
		publishChannel(p, w, s, wsChannelId, scid(2));
		publishChannel(p2, p2, w, p2wChannelId, scid(4));
		publishChannel(p2, w, s, wsChannelId, scid(2));
		publishChannel(s, s, r, srChannelId, scid(3));
		for (const n of [p, p2, w, s, r]) n.handleNewBlock(TIP);
		const world = {
			p,
			s,
			r,
			pConfig: {} as never,
			sConfig: {} as never,
			rConfig: {} as never,
			ps: pw,
			sr,
			psChannelId: pwChannelId,
			srChannelId,
			srHex: srChannelId.toString('hex'),
			errors: { p: [], s: [], r: [] }
		};
		activate(world, { witnessPeers: [Buffer.from(w.getNodeId(), 'hex')] });
		await r.provisionFforWitness(world.srHex, w.getNodeId());
		const bolt11 = r.createFforVoucherInvoice(world.srHex, 1).bolt11;
		const paymentHash = decodeInvoice(bolt11).paymentHash;
		sr.disconnect();

		// The honest settlement: P pays, W records, S settles.
		p.sendPayment(bolt11);
		await waitFor(
			() => p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'first payment'
		);
		const mailboxIdHex = record(r, world.srHex).witnesses[0].mailboxId.toString(
			'hex'
		);
		expect(
			w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex)
		).to.have.length(1);
		const t1 = record(s, world.srHex).preimages[0];
		ws.log.length = 0;

		// The malicious witness: it holds t_1, so when P2 pays the same
		// invoice it settles the inbound HTLC itself and forwards nothing.
		ws.drop = (from, type): boolean =>
			from === w.getNodeId() && type === MessageType.UPDATE_ADD_HTLC;
		w.on(
			'htlc:forward',
			(inChannelId: Buffer, _out: Buffer, _amt: bigint, hash: Buffer) => {
				if (hash.equals(paymentHash) && inChannelId.equals(p2wChannelId)) {
					const inbound = [
						...w
							.getChannelManager()
							.getChannel(p2wChannelId)!
							.getFullState()
							.htlcs.entries()
					].find(
						([k, e]) =>
							k.startsWith('received-') && e.paymentHash.equals(paymentHash)
					);
					if (inbound) {
						w.getChannelManager().fulfillHtlc(p2wChannelId, inbound[1].id, t1);
					}
				}
			}
		);
		p2.sendPayment(bolt11);
		await waitFor(
			() => p2.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'second payment'
		);
		// S never saw the second HTLC; R's records show one settlement.
		expect(
			ws.log.filter((e) => e.type === MessageType.UPDATE_ADD_HTLC)
		).to.have.length(0);
		expect(
			record(s, world.srHex).slotStates.filter((x) => x !== 'UNUSED')
		).to.have.length(1);
		expect(
			w.getFforWitnessService()!.ledger.listRecords(mailboxIdHex)
		).to.have.length(1);
		const fetched = await r.fetchFforWitnessRecords(world.srHex);
		expect(fetched[0].records).to.have.length(1);
		wStorage.close();
	});
});
