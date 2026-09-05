/**
 * M9.3 (spec section 9.6.8): the witness's crash matrix, in process. W is
 * a fresh LightningNode over the same database at each boundary of section
 * 9.6.5, and the oracle is what R can enforce afterwards: exactly the
 * records the steps imply, one upstream fulfil, the payer paid once.
 *
 *  - crash before step 3 (the preimage is durable, the record is not);
 *  - crash after step 3, before step 5 (recorded, not propagated);
 *  - crash after step 5 (recorded and propagated);
 *  - one of two witnesses withholding: R credits from the other;
 *  - a witness serving after close.
 *
 * The section 9.6.8 S-side cells live in ffor-adversarial-recovery.test.ts;
 * the path that omits every witness is the TLV 13 case in
 * ffor-variant-d-m8.test.ts.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { MessageType } from '../../src/lightning/message/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { FforState } from '../../src/lightning/ffor/types';
import {
	IWorld,
	NodeLink,
	TIP,
	activate,
	makeNodeConfig,
	openReadyChannel,
	publishChannel,
	record
} from './helpers/ffor-world';

interface IWitnessWorld extends IWorld {
	w: LightningNode;
	wConfig: INodeConfig;
	wStorage: SqliteStorage;
	pw: NodeLink;
	ws: NodeLink;
	rw: NodeLink;
	pwChannelId: Buffer;
	wsChannelId: Buffer;
}

let seed = 6000;
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

function createWitnessWorld(): IWitnessWorld {
	seed += 10;
	const pConfig = makeNodeConfig(seed + 1);
	const wStorage = new SqliteStorage(':memory:');
	wStorage.open();
	const wConfig = makeNodeConfig(seed + 4, wStorage, {
		fforWitness: { enabled: true, barrierMs: 60_000 }
	});
	const sConfig = makeNodeConfig(seed + 2);
	const rConfig = makeNodeConfig(seed + 3);
	const p = new LightningNode(pConfig);
	const w = new LightningNode(wConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	for (const n of [p, w, s, r]) n.on('node:error', () => {});
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	const pw = new NodeLink(p, w);
	const ws = new NodeLink(w, s);
	const sr = new NodeLink(s, r);
	const rw = new NodeLink(r, w);
	const pwChannelId = openReadyChannel(p, w, 1_000_000n);
	const wsChannelId = openReadyChannel(w, s, 1_000_000n);
	const srChannelId = openReadyChannel(s, r, 1_000_000n);
	const scid = (i: number): Buffer =>
		encodeShortChannelId({ block: 500, txIndex: i, outputIndex: 0 });
	publishChannel(p, p, w, pwChannelId, scid(1));
	publishChannel(p, w, s, wsChannelId, scid(2));
	publishChannel(s, s, r, srChannelId, scid(3));
	for (const n of [p, w, s, r]) n.handleNewBlock(TIP);
	return {
		p,
		s,
		r,
		w,
		wConfig,
		wStorage,
		pConfig,
		sConfig,
		rConfig,
		ps: pw,
		sr,
		pw,
		ws,
		rw,
		psChannelId: pwChannelId,
		pwChannelId,
		wsChannelId,
		srChannelId,
		srHex: srChannelId.toString('hex'),
		errors
	};
}

/** W dies and comes back as a fresh process over its database. */
function restartW(w: IWitnessWorld): void {
	for (const l of [w.pw, w.ws, w.rw]) l.connected = false;
	const wId = w.w.getNodeId();
	for (const [peer, channelId] of [
		[w.p, w.pwChannelId],
		[w.s, w.wsChannelId]
	] as const) {
		if (
			peer.getChannelManager().getChannel(channelId)!.getState() ===
			ChannelState.NORMAL
		) {
			peer.getChannelManager().handlePeerDisconnected(wId);
		}
	}
	const w2 = new LightningNode(w.wConfig);
	w2.on('node:error', () => {});
	w2.handleNewBlock(TIP);
	expect(w2.getNodeId()).to.equal(wId);
	w.w = w2;
	w.pw = new NodeLink(w.p, w2);
	w.ws = new NodeLink(w2, w.s);
	w.rw = new NodeLink(w.r, w2);
	for (const l of [w.pw, w.ws, w.rw]) l.connected = false;
}

function reconnectW(w: IWitnessWorld): void {
	w.ws.reconnect();
	w.pw.reconnect();
	w.rw.connected = true;
}

function mailboxOf(w: IWitnessWorld): string {
	return record(w.r, w.srHex).witnesses[0].mailboxId.toString('hex');
}

function rowsOf(w: IWitnessWorld): number {
	return w.w.getFforWitnessService()!.ledger.listRecords(mailboxOf(w)).length;
}

function fulfilsToP(w: IWitnessWorld, links: NodeLink[]): number {
	return links.reduce(
		(n, l) =>
			n +
			l.log.filter(
				(e) =>
					e.from === w.w.getNodeId() &&
					e.type === MessageType.UPDATE_FULFILL_HTLC
			).length,
		0
	);
}

async function setup(
	w: IWitnessWorld
): Promise<{ bolt11: string; paymentHash: Buffer }> {
	activate(w, { witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')] });
	await w.r.provisionFforWitness(w.srHex, w.w.getNodeId());
	const bolt11 = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
	w.sr.disconnect();
	for (const l of [w.pw, w.ws, w.sr, w.rw]) l.log.length = 0;
	return { bolt11, paymentHash: decodeInvoice(bolt11).paymentHash };
}

/** After the restart: R fetches from W alone and the oracle is what R holds. */
async function oracle(
	w: IWitnessWorld,
	paymentHash: Buffer,
	links: NodeLink[]
): Promise<void> {
	expect(rowsOf(w), 'exactly one record').to.equal(1);
	expect(fulfilsToP(w, links), 'exactly one upstream fulfil ever').to.equal(1);
	expect(w.p.getPayment(paymentHash)!.status).to.equal(PaymentStatus.COMPLETED);
	expect(w.sr.log, 'S sent R nothing').to.have.length(0);
	const fetched = await w.r.fetchFforWitnessRecords(w.srHex);
	expect(fetched[0].records).to.deep.equal([
		{ k: 1, unbarriered: false, verified: true }
	]);
	const t1 = record(w.s, w.srHex).preimages[0];
	expect(record(w.r, w.srHex).knownPreimages[0]!.equals(t1)).to.be.true;
}

describe('FFOR receipt witness crash matrix (M9.3, section 9.6.8)', function () {
	this.timeout(60_000);

	it('W crashes before step 3: the restart records first, then propagates, exactly once', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		const link1 = w.pw;
		// The store refuses, the fulfil is held, and W dies inside the hold.
		let failing = true;
		const original = w.wStorage.saveMetadata.bind(w.wStorage);
		w.wStorage.saveMetadata = (key: string, value: string): void => {
			if (failing && key.startsWith('ffor_witness_record'))
				throw new Error('disk full');
			original(key, value);
		};
		w.p.sendPayment(bolt11);
		await sleep(30);
		expect(rowsOf(w)).to.equal(0);
		expect(w.p.getPayment(paymentHash)!.status).to.equal(PaymentStatus.PENDING);
		failing = false;
		restartW(w);
		reconnectW(w);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the owed pass to record and settle'
		);
		await oracle(w, paymentHash, [link1, w.pw]);
	});

	it('W crashes after step 3, before step 5: the restart propagates the recorded fulfil, no second record', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		const link1 = w.pw;
		// The downstream fulfil lands while the upstream channel is down, so
		// the record is durable and nothing has gone upstream; W then dies.
		w.ws.drop = (from, type): boolean => {
			if (from === w.s.getNodeId() && type === MessageType.UPDATE_FULFILL_HTLC)
				w.pw.disconnect();
			return false;
		};
		w.p.sendPayment(bolt11);
		await sleep(30);
		expect(rowsOf(w)).to.equal(1);
		expect(fulfilsToP(w, [link1])).to.equal(0);
		restartW(w);
		reconnectW(w);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'the owed pass to settle'
		);
		await oracle(w, paymentHash, [link1, w.pw]);
	});

	it('W crashes after step 5: nothing is owed and nothing is duplicated', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		const link1 = w.pw;
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'completion'
		);
		restartW(w);
		reconnectW(w);
		await sleep(50);
		await oracle(w, paymentHash, [link1, w.pw]);
	});

	it('one of two witnesses withholds: R credits from the other and reports the failure', async () => {
		const w = createWitnessWorld();
		// A second witness with its own mailbox.
		const w2Storage = new SqliteStorage(':memory:');
		w2Storage.open();
		const w2 = new LightningNode(
			makeNodeConfig(seed + 9, w2Storage, { fforWitness: { enabled: true } })
		);
		w2.on('node:error', () => {});
		w2.handleNewBlock(TIP);
		const rw2 = new NodeLink(w.r, w2);
		activate(w, { witnessPeers: [Buffer.from(w.w.getNodeId(), 'hex')] });
		await w.r.provisionFforWitness(w.srHex, w.w.getNodeId());
		await w.r.provisionFforWitness(w.srHex, w2.getNodeId());
		expect(record(w.r, w.srHex).witnesses).to.have.length(2);
		const bolt11 = w.r.createFforVoucherInvoice(w.srHex, 1).bolt11;
		const paymentHash = decodeInvoice(bolt11).paymentHash;
		w.sr.disconnect();
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'completion'
		);
		// W2 was not on the path (it recorded nothing) and now withholds
		// everything: it never answers. W answers.
		rw2.connected = false;
		const fetched = await w.r.fetchFforWitnessRecords(w.srHex, undefined, 200);
		const byId = new Map(
			fetched.map((f) => [f.witnessNodeId.toString('hex'), f])
		);
		expect(byId.get(w.w.getNodeId())!.credited).to.equal(1);
		expect(byId.get(w2.getNodeId())!.ok).to.be.false;
		expect(byId.get(w2.getNodeId())!.error).to.match(/did not answer/);
		expect(record(w.r, w.srHex).knownPreimages[0]).to.not.equal(null);
		w2Storage.close();
	});

	it('after close the witness creates no record for a late fulfil but keeps serving what it holds, and rescue closes the epoch', async () => {
		const w = createWitnessWorld();
		const { bolt11, paymentHash } = await setup(w);
		w.p.sendPayment(bolt11);
		await waitFor(
			() => w.p.getPayment(paymentHash)?.status === PaymentStatus.COMPLETED,
			'completion'
		);
		// R returns: rescue fetches, credits, and closes cooperatively.
		w.sr.reconnect();
		const rescued = await w.r.rescueFforEpoch(w.srHex);
		expect(rescued.preimagesKnown).to.deep.equal([1]);
		expect(rescued.action).to.equal('closed');
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		const closed = await w.r.closeFforWitnesses(w.srHex);
		expect(closed[0]).to.deep.include({ ok: true, held: 1 });
		const service = w.w.getFforWitnessService()!;
		expect(service.ledger.mailbox(mailboxOf(w))!.state).to.equal('CLOSED');
		// Records are still served after close, and a fulfil now is not recorded.
		const again = await w.r.fetchFforWitnessRecords(w.srHex);
		expect(again[0].records).to.have.length(1);
		expect(
			service.interceptDownstreamFulfil({
				outKey: 'late:offered-1',
				preimage: record(w.s, w.srHex).preimages[0],
				paymentHash,
				amountInMsat: 0n,
				amountOutMsat: 0n,
				outgoingCltv: 0,
				incomingCltvExpiry: 0
			})
		).to.equal('none');
	});
});
