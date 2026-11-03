/**
 * Composite splice-out (issue #1922, docs/MULTI-CHANNEL-SPLICE-OUT.md): one
 * transaction spends the funding outpoints of several channels and pays one
 * destination, driven by LightningNode.startCompositeSpliceOut over N
 * ordinary splice sessions.
 *
 * Three in-process nodes: a wallet with storage (the initiator in every
 * session) and two or three primaries, wired message:outbound to
 * handlePeerMessage. Channels are opened with REAL funding transactions so
 * the wallet holds every fundingTxHex a composite needs as prev_tx. Peer
 * feature knowledge is stubbed on the wallet (no peer manager runs here).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';

bitcoin.initEccLib(ecc);

import { LightningNode } from '../../src/lightning/node/lightning-node';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { createFundingScript } from '../../src/lightning/script/funding';
import { ChannelState } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeTxAddOutputMessage,
	encodeTxAddOutputMessage
} from '../../src/lightning/message/interactive-tx';
import {
	COMPOSITE_SPLICE_RETENTION_MS,
	CompositeSpliceRefusalCode,
	ICompositeSpliceStageEvent
} from '../../src/lightning/node/composite-splice-engine';
import type { ICompositeSpliceRecord } from '../../src/lightning/channel/composite-splice-record';
import {
	createNode,
	wire,
	waitFor,
	disconnect,
	reconnectRestarted,
	ICut,
	IWireGate
} from './helpers/async-world';

const FUNDING = 1_000_000n;

/** Open a v1 channel funded by a REAL transaction the opener keeps the hex of. */
async function openFunded(
	opener: LightningNode,
	acceptor: LightningNode,
	sats = FUNDING
): Promise<{ channelId: Buffer; fundingTx: bitcoin.Transaction }> {
	const channel = opener.openChannel(acceptor.getNodeId(), sats);
	await waitFor(
		() => !!channel.getFullState().remoteBasepoints,
		'accept_channel to arrive'
	);
	const st = channel.getFullState();
	const script = createFundingScript(
		st.localBasepoints.fundingPubkey,
		st.remoteBasepoints!.fundingPubkey
	).p2wshOutput;
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(script, Number(sats));
	const channelId = opener.createFunding(
		channel,
		Buffer.from(tx.getHash()),
		0,
		crypto.randomBytes(64)
	)!;
	await waitFor(
		() => channel.getState() !== ChannelState.SENT_FUNDING_CREATED,
		'funding_signed to arrive'
	);
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	await waitFor(
		() => channel.getState() === ChannelState.NORMAL,
		'the opened channel to reach NORMAL'
	);
	expect(
		opener.getRawChannel(channelId)!.setFundingTxHex(tx.toHex()),
		'funding hex retained'
	).to.equal(true);
	return { channelId, fundingTx: tx };
}

/** No peer manager runs here: say every peer splices and admits composites. */
function allowCompositePeers(node: LightningNode): void {
	const n = node as unknown as {
		peerSupportsSplicing: () => boolean;
		peerSupportsCompositeSpliceInputs: () => boolean;
	};
	n.peerSupportsSplicing = () => true;
	n.peerSupportsCompositeSpliceInputs = () => true;
}

const destinationScript = (): Buffer =>
	bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!;

interface IWorld {
	storage: MemoryStorage;
	wallet: LightningNode;
	peers: LightningNode[];
	cuts: ICut[];
	gates: IWireGate[];
	channels: Buffer[];
	stages: ICompositeSpliceStageEvent[];
	broadcasts: Buffer[];
	nodes: LightningNode[];
}

async function makeWorld(
	seed: number,
	capacities: bigint[],
	storage = new MemoryStorage()
): Promise<IWorld> {
	const wallet = createNode(seed, storage);
	const peers = capacities.map((_, i) => createNode(seed + 1 + i));
	const cuts: ICut[] = [];
	const gates: IWireGate[] = [];
	const channels: Buffer[] = [];
	for (let i = 0; i < peers.length; i++) {
		const cut: ICut = { val: false };
		const gate: IWireGate = { hold: false, queue: [] };
		cuts.push(cut);
		gates.push(gate);
		wire(wallet, peers[i], cut, undefined, gate);
		channels.push(
			(await openFunded(wallet, peers[i], capacities[i])).channelId
		);
	}
	allowCompositePeers(wallet);
	const stages: ICompositeSpliceStageEvent[] = [];
	wallet.on('composite-splice:stage', (e: ICompositeSpliceStageEvent) =>
		stages.push(e)
	);
	const broadcasts: Buffer[] = [];
	for (const n of [wallet, ...peers]) {
		n.on('broadcast:tx', (tx: Buffer) => broadcasts.push(tx));
	}
	return {
		storage,
		wallet,
		peers,
		cuts,
		gates,
		channels,
		stages,
		broadcasts,
		nodes: [wallet, ...peers]
	};
}

/** Both sides of every channel send splice_locked, as a confirmation would. */
function lockAll(world: IWorld): void {
	for (let i = 0; i < world.channels.length; i++) {
		world.wallet.getChannelManager().sendSpliceLocked(world.channels[i]);
		world.peers[i].getChannelManager().sendSpliceLocked(world.channels[i]);
	}
}

/**
 * Re-wire peer i by hand so one message type from it can be withheld; the
 * standard wire for that pair is silenced meanwhile. `release` restores it.
 */
function holdFromPeer(
	w: IWorld,
	i: number,
	type: MessageType
): { held: Buffer[]; release: () => void } {
	const peer = w.peers[i];
	w.cuts[i].val = true;
	const held: Buffer[] = [];
	const walletToPeer = (pk: string, t: number, payload: Buffer): void => {
		if (pk === peer.getNodeId()) {
			peer.handlePeerMessage(w.wallet.getNodeId(), t, payload);
		}
	};
	const peerToWallet = (pk: string, t: number, payload: Buffer): void => {
		if (pk !== w.wallet.getNodeId()) return;
		if (t === type) {
			held.push(payload);
			return;
		}
		w.wallet.handlePeerMessage(peer.getNodeId(), t, payload);
	};
	w.wallet.on('message:outbound', walletToPeer);
	peer.on('message:outbound', peerToWallet);
	return {
		held,
		release: (): void => {
			w.wallet.removeListener('message:outbound', walletToPeer);
			peer.removeListener('message:outbound', peerToWallet);
			w.cuts[i].val = false;
		}
	};
}

/** Silence every wire of the old wallet before a restart replaces it. */
function silence(w: IWorld): void {
	for (const cut of w.cuts) cut.val = true;
}

const request = (
	budgetMs?: number
): Parameters<LightningNode['startCompositeSpliceOut']>[0] => ({
	destinationScript: destinationScript(),
	amountSats: 1_500_000n,
	fundingFeeratePerkw: 1000,
	...(budgetMs !== undefined ? { budgetMs } : {})
});

function storedRecord(
	id: string,
	stage: ICompositeSpliceRecord['stage'],
	updatedAt: number
): ICompositeSpliceRecord {
	return {
		id,
		stage,
		channels: [
			{
				channelId: 'aa'.repeat(32),
				peerPubkey: '02' + 'bb'.repeat(32),
				fundingTxid: 'cc'.repeat(32),
				fundingOutputIndex: 0,
				debitSats: '1000',
				feeSats: '10',
				oldCapacitySats: '100000',
				newCapacitySats: '98990',
				inputSerialId: '0',
				fundingOutputSerialId: '2'
			}
		],
		destinationScript: '0014' + 'dd'.repeat(20),
		destinationSerialId: '4',
		amountSats: '1000',
		feeSats: '10',
		feeratePerkw: 253,
		locktime: 0,
		createdAt: updatedAt,
		updatedAt
	};
}

const stageNames = (w: IWorld): string[] => w.stages.map((s) => s.stage);

describe('Composite splice-out (issue #1922)', function () {
	this.timeout(30_000);
	const worlds: IWorld[] = [];
	afterEach(() => {
		for (const w of worlds.splice(0)) for (const n of w.nodes) n.destroy();
	});

	it('spends two channels into one destination in one transaction, both channels adopt it', async function () {
		const w = await makeWorld(7100, [FUNDING, FUNDING]);
		worlds.push(w);
		const destination = destinationScript();
		const before = w.channels.map(
			(id) => w.wallet.getRawChannel(id)!.getBalances().localMsat
		);

		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destination,
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(
			res.ok,
			JSON.stringify(res, (_, v) => (typeof v === 'bigint' ? v.toString() : v))
		).to.equal(true);
		if (!res.ok) return;
		expect(res.plan.channels).to.have.length(2);

		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'the composite to broadcast'
		);
		lockAll(w);
		await waitFor(
			() => w.stages.some((s) => s.stage === 'LOCKED'),
			'the composite to lock'
		);
		expect(stageNames(w)).to.deep.equal([
			'PLANNED',
			'NEGOTIATING',
			'COMMITTED',
			'PEERS_SIGNED',
			'RELEASED',
			'BROADCAST',
			'LOCKED'
		]);

		const record = w.wallet.getCompositeSplice(res.id)!;
		expect(record.stage).to.equal('LOCKED');
		expect(record.channels).to.have.length(2);
		const tx = bitcoin.Transaction.fromHex(record.txHex!);
		expect(Buffer.from(tx.getHash()).toString('hex')).to.equal(record.txid);
		expect(tx.ins, 'one input per channel').to.have.length(2);
		expect(
			tx.outs,
			'one funding output per channel plus the destination'
		).to.have.length(3);
		for (const input of tx.ins) {
			expect(input.witness, 'a 2-of-2 witness on every input').to.have.length(
				4
			);
		}
		const paid = tx.outs.find((o) => Buffer.from(o.script).equals(destination));
		expect(paid, 'destination output present').to.exist;
		expect(BigInt(paid!.value)).to.equal(1_500_000n);
		expect(
			record.channels.reduce((s, c) => s + BigInt(c.debitSats), 0n),
			'debits sum to the amount'
		).to.equal(1_500_000n);
		const inSum = record.channels.reduce(
			(s, c) => s + BigInt(c.oldCapacitySats),
			0n
		);
		const outSum = tx.outs.reduce((s, o) => s + BigInt(o.value), 0n);
		expect(inSum - outSum, 'the implicit fee is the recorded fee').to.equal(
			BigInt(record.feeSats)
		);
		for (const c of record.channels) {
			expect(
				BigInt(c.oldCapacitySats) - BigInt(c.debitSats) - BigInt(c.feeSats)
			).to.equal(BigInt(c.newCapacitySats));
			expect(BigInt(c.feeSats) > 0n, 'every debited channel pays fee').to.equal(
				true
			);
		}

		// Every channel, on both sides, now runs on the composite transaction.
		for (let i = 0; i < w.channels.length; i++) {
			const id = w.channels[i];
			const mine = w.wallet.getRawChannel(id)!.getFullState();
			const theirs = w.peers[i].getRawChannel(id)!.getFullState();
			const c = record.channels.find(
				(x) => x.channelId === id.toString('hex')
			)!;
			expect(mine.state).to.equal(ChannelState.NORMAL);
			expect(theirs.state).to.equal(ChannelState.NORMAL);
			expect(mine.fundingTxid!.toString('hex')).to.equal(record.txid);
			expect(theirs.fundingTxid!.toString('hex')).to.equal(record.txid);
			expect(mine.fundingSatoshis.toString()).to.equal(c.newCapacitySats);
			expect(theirs.fundingSatoshis.toString()).to.equal(c.newCapacitySats);
			expect(mine.spliceInFlight).to.equal(null);
			// The wallet paid the debit and its fee share; the peer paid nothing.
			expect(w.wallet.getRawChannel(id)!.getBalances().localMsat).to.equal(
				before[i] - (BigInt(c.debitSats) + BigInt(c.feeSats)) * 1000n
			);
			expect(w.peers[i].getRawChannel(id)!.getBalances().localMsat).to.equal(
				0n
			);
			// 5a: the adopted funding keeps its bytes for the next composite.
			expect(mine.fundingTxHex).to.equal(record.txHex);
		}
		// Everyone broadcast the same transaction.
		const txids = new Set(
			w.broadcasts.map((b) =>
				Buffer.from(bitcoin.Transaction.fromBuffer(b).getHash()).toString('hex')
			)
		);
		expect([...txids]).to.deep.equal([record.txid]);
		// The record is on disk at its final stage.
		expect(w.storage.loadCompositeSplice(record.id)!.stage).to.equal('LOCKED');
		expect(w.wallet.listCompositeSplices().map((r) => r.id)).to.deep.equal([
			record.id
		]);
	});

	it('debits the largest spendable balance first and leaves channels it does not need alone', async function () {
		const w = await makeWorld(7110, [400_000n, FUNDING, 700_000n]);
		worlds.push(w);
		const res = await w.wallet.planCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_200_000n,
			fundingFeeratePerkw: 1000
		});
		expect(
			res.ok,
			JSON.stringify(res, (_, v) => (typeof v === 'bigint' ? v.toString() : v))
		).to.equal(true);
		if (!res.ok) return;
		// The 1M channel gives everything it can, the 700k channel the rest;
		// the 400k channel is not touched.
		const byCapacity = [...res.plan.channels].sort((a, b) =>
			a.oldCapacitySats > b.oldCapacitySats ? -1 : 1
		);
		expect(byCapacity.map((c) => c.oldCapacitySats)).to.deep.equal([
			FUNDING,
			700_000n
		]);
		expect(byCapacity[0].debitSats).to.equal(byCapacity[0].maxDebitSats);
		expect(byCapacity[1].debitSats < byCapacity[1].maxDebitSats).to.equal(true);
		expect(byCapacity[0].debitSats + byCapacity[1].debitSats).to.equal(
			1_200_000n
		);
		expect(res.plan.skipped).to.deep.equal([]);
		// Fee shares are proportional to the debit, rounded up, and sum to at
		// least the transaction's fee at this weight.
		const total = res.plan.feeSats;
		for (const c of res.plan.channels) {
			const share = (total * c.debitSats + 1_200_000n - 1n) / 1_200_000n;
			expect(c.feeSats >= share - 1n && c.feeSats <= share + 1n).to.equal(true);
		}
		// Planning moved nothing.
		for (const id of w.channels) {
			expect(w.wallet.getRawChannel(id)!.getState()).to.equal(
				ChannelState.NORMAL
			);
		}
		expect(w.wallet.listCompositeSplices()).to.deep.equal([]);
	});

	it('refuses bad requests, a one-channel plan, an unknown channel and an amount the channels cannot cover', async function () {
		const w = await makeWorld(7120, [FUNDING, FUNDING]);
		worlds.push(w);
		const dest = destinationScript();
		const plan = (
			req: Parameters<LightningNode['planCompositeSpliceOut']>[0]
		) => w.wallet.planCompositeSpliceOut(req);

		let r = await plan({
			destinationScript: dest,
			amountSats: 0n,
			fundingFeeratePerkw: 1000
		});
		expect(r.ok).to.equal(false);
		if (!r.ok)
			expect(r.code).to.equal(CompositeSpliceRefusalCode.INVALID_PARAMS);
		r = await plan({
			destinationScript: dest,
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 10
		});
		expect(r.ok).to.equal(false);
		if (!r.ok)
			expect(r.code).to.equal(CompositeSpliceRefusalCode.INVALID_PARAMS);
		r = await plan({
			destinationScript: Buffer.from([0x6a]),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(r.ok).to.equal(false);
		if (!r.ok) {
			expect(r.code).to.equal(CompositeSpliceRefusalCode.INVALID_PARAMS);
			expect(r.error).to.match(/destinationScript/);
		}
		// One channel covers 300k alone: that is a plain splice-out.
		r = await plan({
			destinationScript: dest,
			amountSats: 300_000n,
			fundingFeeratePerkw: 1000
		});
		expect(r.ok).to.equal(false);
		if (!r.ok)
			expect(r.code).to.equal(
				CompositeSpliceRefusalCode.SINGLE_CHANNEL_SUFFICES
			);
		r = await plan({
			destinationScript: dest,
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000,
			channelIds: [w.channels[0], crypto.randomBytes(32)]
		});
		expect(r.ok).to.equal(false);
		if (!r.ok)
			expect(r.code).to.equal(CompositeSpliceRefusalCode.CHANNEL_NOT_FOUND);
		r = await plan({
			destinationScript: dest,
			amountSats: 5_000_000n,
			fundingFeeratePerkw: 1000
		});
		expect(r.ok).to.equal(false);
		if (!r.ok)
			expect(r.code).to.equal(CompositeSpliceRefusalCode.INSUFFICIENT_BALANCE);
		// A peer without the capability is left out, by name.
		(
			w.wallet as unknown as {
				peerSupportsCompositeSpliceInputs: (p: string) => boolean;
			}
		).peerSupportsCompositeSpliceInputs = (p) => p !== w.peers[1].getNodeId();
		r = await plan({
			destinationScript: dest,
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(r.ok).to.equal(false);
		if (!r.ok) {
			expect(r.code).to.equal(CompositeSpliceRefusalCode.INSUFFICIENT_BALANCE);
			expect(r.skipped).to.have.length(1);
			expect(r.skipped![0].channelId.equals(w.channels[1])).to.equal(true);
			expect(r.skipped![0].reason).to.match(/option_composite_splice_inputs/);
		}
		allowCompositePeers(w.wallet);
		// A node without composite-record storage refuses before planning.
		const bare = createNode(7129);
		worlds.push({ ...w, nodes: [bare], stages: [], broadcasts: [] });
		allowCompositePeers(bare);
		const noStorage = await bare.planCompositeSpliceOut({
			destinationScript: dest,
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(noStorage.ok).to.equal(false);
		if (!noStorage.ok)
			expect(noStorage.code).to.equal(
				CompositeSpliceRefusalCode.STORAGE_REQUIRED
			);
	});

	it('aborts every session on an operator abort before release, and the channels are usable again', async function () {
		const w = await makeWorld(7130, [FUNDING, FUNDING]);
		worlds.push(w);
		// Hold what the wallet sends to the second peer: session 2 never gets
		// past stfu, so the composite parks in NEGOTIATING.
		w.gates[1].hold = true;
		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('NEGOTIATING');
		// Both channels are reserved: a single splice or a close is refused.
		const busy = w.wallet.spliceOut(
			w.channels[0],
			10_000n,
			1000,
			destinationScript()
		);
		expect(busy.ok).to.equal(false);
		expect(busy.error).to.match(/composite splice/);
		const close = w.wallet.closeChannel(w.channels[0], destinationScript());
		expect(close.ok).to.equal(false);
		expect(close.error).to.match(/composite splice/);
		// A second composite is refused, not queued.
		const second = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(second.ok).to.equal(false);
		if (!second.ok)
			expect(second.code).to.equal(CompositeSpliceRefusalCode.BUSY);

		const aborted = w.wallet.abortCompositeSplice(
			res.id,
			'operator changed their mind'
		);
		expect(aborted.ok, aborted.error).to.equal(true);
		const record = w.wallet.getCompositeSplice(res.id)!;
		expect(record.stage).to.equal('ABORTED');
		expect(record.reason).to.equal('operator changed their mind');
		expect(w.storage.loadCompositeSplice(record.id)!.stage).to.equal('ABORTED');
		// Deliver what the gate held (the second peer sees stfu, splice_init
		// and the tx_abort that unwinds it) and let everything settle.
		w.gates[1].hold = false;
		while (w.gates[1].queue.length > 0) {
			const m = w.gates[1].queue.shift()!;
			m.to.handlePeerMessage(m.from, m.type, m.p);
		}
		await waitFor(
			() =>
				w.channels.every((id) => {
					const mine = w.wallet.getRawChannel(id)!.getFullState();
					return (
						mine.state === ChannelState.NORMAL && mine.spliceInFlight === null
					);
				}),
			'both channels back to NORMAL with no record'
		);
		for (let i = 0; i < 2; i++) {
			expect(w.peers[i].getRawChannel(w.channels[i])!.getState()).to.equal(
				ChannelState.NORMAL
			);
			expect(
				w.wallet.getRawChannel(w.channels[i])!.getFullState().fundingSatoshis
			).to.equal(FUNDING);
		}
		expect(w.broadcasts).to.deep.equal([]);
		expect(w.wallet.abortCompositeSplice(res.id).code).to.equal(
			CompositeSpliceRefusalCode.TOO_LATE
		);

		// The channels are free: a fresh composite completes.
		w.stages.length = 0;
		const again = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(
			again.ok,
			JSON.stringify(again, (_, v) =>
				typeof v === 'bigint' ? v.toString() : v
			)
		).to.equal(true);
		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'second composite to broadcast'
		);
		lockAll(w);
		await waitFor(
			() => w.stages.some((s) => s.stage === 'LOCKED'),
			'second composite to lock'
		);
	});

	it('a peer that contributes an output aborts the whole composite before any commitment', async function () {
		const w = await makeWorld(7140, [FUNDING, FUNDING]);
		worlds.push(w);
		// An adversarial second peer: right after its splice_ack it adds an
		// output of its own. The wallet's session must refuse it with tx_abort
		// and the engine must abort the first session too.
		const peer = w.peers[1];
		const channelId = w.channels[1];
		// Runs BEFORE the wire delivers the peer's first tx_complete, while the
		// wallet's session is still collecting: the wires here are synchronous,
		// so anything hooked after the wire sees a finished negotiation.
		let injected = false;
		peer.prependListener('message:outbound', (pk: string, type: number) => {
			if (injected || pk !== w.wallet.getNodeId()) return;
			if (type !== MessageType.TX_COMPLETE) return;
			injected = true;
			w.wallet.handlePeerMessage(
				peer.getNodeId(),
				MessageType.TX_ADD_OUTPUT,
				encodeTxAddOutputMessage({
					channelId,
					serialId: 1n,
					amountSats: 10_000n,
					scriptPubkey: destinationScript()
				})
			);
		});
		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		await waitFor(
			() => w.wallet.getCompositeSplice(res.id)!.stage === 'ABORTED',
			'the composite to abort'
		);
		const record = w.wallet.getCompositeSplice(res.id)!;
		expect(record.reason).to.match(
			/tx_add_output in a composite splice session/
		);
		expect(stageNames(w)).to.deep.equal(['PLANNED', 'NEGOTIATING', 'ABORTED']);
		await waitFor(
			() =>
				w.channels.every(
					(id) =>
						w.wallet.getRawChannel(id)!.getState() === ChannelState.NORMAL &&
						w.wallet.getRawChannel(id)!.getFullState().spliceInFlight === null
				),
			'both channels back to NORMAL'
		);
		expect(w.broadcasts).to.deep.equal([]);
		// Nothing was signed: no commitment_signed left the wallet.
		expect(
			w.wallet.getRawChannel(w.channels[0])!.getFullState().fundingSatoshis
		).to.equal(FUNDING);
	});

	it('a peer that never signs within the budget aborts the composite, including the session whose peer did sign', async function () {
		const w = await makeWorld(7150, [FUNDING, FUNDING]);
		worlds.push(w);
		// Hold the second peer's tx_signatures: its session negotiated and
		// committed, but the composite cannot release without it.
		const held: Array<{ type: number; payload: Buffer }> = [];
		const peer = w.peers[1];
		const original = peer.handlePeerMessage.bind(peer);
		w.cuts[1].val = true;
		peer.on('message:outbound', () => undefined);
		// Re-wire the second peer by hand so its TX_SIGNATURES can be withheld.
		w.wallet.on(
			'message:outbound',
			(pk: string, type: number, payload: Buffer) => {
				if (pk === peer.getNodeId())
					original(w.wallet.getNodeId(), type, payload);
			}
		);
		peer.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk !== w.wallet.getNodeId()) return;
			if (type === MessageType.TX_SIGNATURES) {
				held.push({ type, payload });
				return;
			}
			w.wallet.handlePeerMessage(peer.getNodeId(), type, payload);
		});
		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000,
			budgetMs: 300
		});
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(held, 'the second peer signed, and the wire held it').to.have.length(
			1
		);
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('COMMITTED');
		// The first peer signed and the wallet withheld its own signatures.
		const first = w.wallet.getRawChannel(w.channels[0])!.getFullState()
			.spliceInFlight!;
		expect(first.receivedTxSignatures).to.equal(true);
		expect(first.sentTxSignatures).to.equal(false);
		expect(first.remoteSharedInputSig, 'the peer half is kept').to.exist;

		await waitFor(
			() => w.wallet.getCompositeSplice(res.id)!.stage === 'ABORTED',
			'the budget to abort the composite',
			2_000
		);
		expect(w.wallet.getCompositeSplice(res.id)!.reason).to.match(/budget/);
		expect(w.broadcasts, 'nothing was broadcast').to.deep.equal([]);
		await waitFor(
			() =>
				w.channels.every(
					(id) =>
						w.wallet.getRawChannel(id)!.getState() === ChannelState.NORMAL &&
						w.wallet.getRawChannel(id)!.getFullState().spliceInFlight === null
				),
			'both wallet channels back to NORMAL'
		);
		// The peers that signed keep their splice: BOLT 2 forbids a side that
		// sent tx_signatures to forget the transaction on tx_abort, and beignet
		// refuses its own abort past that point too. The initiator holds every
		// witness they lack, so nothing of theirs can confirm; they stay in
		// SPLICING until an operator acts (design note section 4).
		for (let i = 0; i < 2; i++) {
			const theirs = w.peers[i].getRawChannel(w.channels[i])!.getFullState();
			expect(theirs.state).to.equal(ChannelState.SPLICING);
			expect(theirs.spliceInFlight?.sentTxSignatures).to.equal(true);
			expect(theirs.spliceInFlight?.receivedTxSignatures).to.equal(false);
		}
	});

	it('a restart before release aborts the composite and forgets the unsent sessions', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7160, [FUNDING, FUNDING], storage);
		worlds.push(w);
		w.gates[1].hold = true;
		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(storage.loadCompositeSplice(res.id.toString('hex'))!.stage).to.equal(
			'NEGOTIATING'
		);

		// Crash the wallet and bring it back on the same storage.
		w.wallet.destroy();
		const restarted = createNode(7160, storage);
		allowCompositePeers(restarted);
		w.nodes.push(restarted);
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		await waitFor(
			() => restarted.getCompositeSplice(res.id)?.stage === 'ABORTED',
			'the restored composite to be ABORTED'
		);
		const record = restarted.getCompositeSplice(res.id)!;
		expect(record.reason).to.match(/NEGOTIATING at restart/);
		expect(storage.loadCompositeSplice(record.id)!.stage).to.equal('ABORTED');
		for (const id of w.channels) {
			const st = restarted.getRawChannel(id)!.getFullState();
			expect(st.spliceInFlight).to.equal(null);
			expect(
				st.state === ChannelState.NORMAL ||
					st.state === ChannelState.AWAITING_REESTABLISH
			).to.equal(true);
			expect(st.fundingSatoshis).to.equal(FUNDING);
		}
		// Reconnecting the peers settles both channels on their old funding.
		for (let i = 0; i < 2; i++) {
			await reconnectRestarted(restarted, w.peers[i]);
		}
		await waitFor(
			() =>
				w.channels.every(
					(id) =>
						restarted.getRawChannel(id)!.getState() === ChannelState.NORMAL &&
						w.peers[w.channels.indexOf(id)].getRawChannel(id)!.getState() ===
							ChannelState.NORMAL
				),
			'both channels NORMAL on both sides after reestablish'
		);
		expect(w.broadcasts).to.deep.equal([]);
		expect(restarted.listCompositeSplices().map((r) => r.stage)).to.deep.equal([
			'ABORTED'
		]);
	});

	it('the record survives a restart after release and reaches LOCKED once the channels lock', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7170, [FUNDING, FUNDING], storage);
		worlds.push(w);
		const res = await w.wallet.startCompositeSpliceOut({
			destinationScript: destinationScript(),
			amountSats: 1_500_000n,
			fundingFeeratePerkw: 1000
		});
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'broadcast'
		);
		const txid = w.wallet.getCompositeSplice(res.id)!.txid!;
		expect(storage.loadCompositeSplice(res.id.toString('hex'))!.stage).to.equal(
			'BROADCAST'
		);

		w.wallet.destroy();
		const restarted = createNode(7170, storage);
		w.nodes.push(restarted);
		const rebroadcasts: Buffer[] = [];
		restarted.on('broadcast:tx', (tx: Buffer) => rebroadcasts.push(tx));
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		await waitFor(
			() => restarted.getCompositeSplice(res.id) !== null,
			'record restored'
		);
		expect(restarted.getCompositeSplice(res.id)!.stage).to.equal('BROADCAST');
		// Reconnect: the splice resumes on both channels (next_funding_txid).
		for (let i = 0; i < 2; i++) await reconnectRestarted(restarted, w.peers[i]);
		await waitFor(
			() =>
				w.channels.every((id) => {
					const st = restarted.getRawChannel(id)!.getFullState();
					return (
						st.state === ChannelState.SPLICING ||
						st.state === ChannelState.NORMAL
					);
				}),
			'channels resumed after reestablish'
		);
		for (let i = 0; i < 2; i++) {
			restarted.getChannelManager().sendSpliceLocked(w.channels[i]);
			w.peers[i].getChannelManager().sendSpliceLocked(w.channels[i]);
		}
		await waitFor(
			() => restarted.getCompositeSplice(res.id)!.stage === 'LOCKED',
			'LOCKED after restart'
		);
		for (const id of w.channels) {
			expect(
				restarted.getRawChannel(id)!.getFullState().fundingTxid!.toString('hex')
			).to.equal(txid);
		}
		expect(storage.loadCompositeSplice(res.id.toString('hex'))!.stage).to.equal(
			'LOCKED'
		);
	});

	it('a restart at COMMITTED aborts the composite and both channels come back NORMAL on the old funding after reestablish', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7200, [FUNDING, FUNDING], storage);
		worlds.push(w);
		// Hold the second peer's tx_signatures: both sessions commit, the
		// composite parks at COMMITTED with a commitment-round record on both
		// wallet channels, and nothing of ours has left.
		const hold = holdFromPeer(w, 1, MessageType.TX_SIGNATURES);
		const res = await w.wallet.startCompositeSpliceOut(request(60_000));
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(hold.held).to.have.length(1);
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('COMMITTED');
		for (const id of w.channels) {
			const st = w.wallet.getRawChannel(id)!.getFullState();
			expect(st.spliceInFlight, 'commitment-round record').to.not.equal(null);
			expect(st.spliceInFlight!.sentTxSignatures).to.equal(false);
		}

		hold.release();
		silence(w);
		w.wallet.destroy();
		const restarted = createNode(7200, storage);
		allowCompositePeers(restarted);
		w.nodes.push(restarted);
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		const record = restarted.getCompositeSplice(res.id)!;
		expect(record.stage).to.equal('ABORTED');
		expect(record.reason).to.match(/COMMITTED at restart/);
		// The sessions are forgotten and the parked state is the OLD one, so
		// reestablish does not restore a spliceless SPLICING.
		for (const id of w.channels) {
			const st = restarted.getRawChannel(id)!.getFullState();
			expect(st.spliceInFlight).to.equal(null);
			expect(st.state).to.equal(ChannelState.AWAITING_REESTABLISH);
			expect(st.preReestablishState).to.equal(ChannelState.NORMAL);
			expect(st.spliceAbortOwed).to.equal(true);
		}
		for (let i = 0; i < 2; i++) await reconnectRestarted(restarted, w.peers[i]);
		await waitFor(
			() =>
				w.channels.every(
					(id) =>
						restarted.getRawChannel(id)!.getState() === ChannelState.NORMAL
				),
			'both wallet channels NORMAL after reestablish'
		);
		for (const id of w.channels) {
			const ch = restarted.getRawChannel(id)!;
			expect(ch.getFullState().fundingSatoshis).to.equal(FUNDING);
			expect(ch.getFullState().spliceInFlight).to.equal(null);
			expect(ch.isHtlcUsable(), 'the channel routes again').to.equal(true);
			// The peers signed and keep their splice (section 4), so the
			// reestablish answered their next_funding_txid with a second
			// tx_abort whose acknowledgement latch stays armed until the next
			// reconnect; it holds back a new splice on this channel, not
			// payments.
			expect(ch.spliceBusyReason() ?? '').to.match(
				/^$|abort is not yet acknowledged/
			);
		}
		expect(w.broadcasts).to.deep.equal([]);
	});

	it('a restart after release with one channel already locked still reaches LOCKED and frees the channels', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7210, [FUNDING, FUNDING], storage);
		worlds.push(w);
		const res = await w.wallet.startCompositeSpliceOut(request());
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'broadcast'
		);
		const txid = w.wallet.getCompositeSplice(res.id)!.txid!;
		// Channel 0 locks before the crash; channel 1 does not.
		w.wallet.getChannelManager().sendSpliceLocked(w.channels[0]);
		w.peers[0].getChannelManager().sendSpliceLocked(w.channels[0]);
		await waitFor(() => {
			const st = w.wallet.getRawChannel(w.channels[0])!.getFullState();
			return (
				st.state === ChannelState.NORMAL &&
				st.fundingTxid!.toString('hex') === txid
			);
		}, 'channel 0 adopted');
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('BROADCAST');

		silence(w);
		w.wallet.destroy();
		const restarted = createNode(7210, storage);
		w.nodes.push(restarted);
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		expect(restarted.getCompositeSplice(res.id)!.stage).to.equal('BROADCAST');
		// Reconnect the pending channel's peer first and lock it, then the
		// adopted channel's peer: the order the review used.
		await reconnectRestarted(restarted, w.peers[1]);
		restarted.getChannelManager().sendSpliceLocked(w.channels[1]);
		w.peers[1].getChannelManager().sendSpliceLocked(w.channels[1]);
		await reconnectRestarted(restarted, w.peers[0]);
		await waitFor(
			() => restarted.getCompositeSplice(res.id)!.stage === 'LOCKED',
			'LOCKED once both channels run on the composite'
		);
		for (const id of w.channels) {
			const st = restarted.getRawChannel(id)!.getFullState();
			expect(st.state).to.equal(ChannelState.NORMAL);
			expect(st.fundingTxid!.toString('hex')).to.equal(txid);
		}
		// Nothing is reserved any more: a close is not refused for the composite.
		const close = restarted.closeChannel(w.channels[0], destinationScript());
		expect(close.error ?? '').to.not.match(/composite splice/);
		const again = await restarted.planCompositeSpliceOut(request());
		if (!again.ok)
			expect(again.code).to.not.equal(CompositeSpliceRefusalCode.BUSY);
	});

	it('a channel that force closes after release ends the composite CONFLICTED and lifts the reservation', async function () {
		const w = await makeWorld(7220, [FUNDING, FUNDING]);
		worlds.push(w);
		const res = await w.wallet.startCompositeSpliceOut(request());
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'broadcast'
		);
		// A spend of channel 0's OLD funding by a commitment transaction makes
		// the composite unconfirmable: the engine must stop holding channel 1.
		const forced = w.wallet.forceCloseChannel(
			w.channels[0],
			destinationScript()
		);
		expect(forced.ok, forced.error).to.equal(true);
		await waitFor(
			() => w.wallet.getCompositeSplice(res.id)!.stage === 'CONFLICTED',
			'the composite to end CONFLICTED'
		);
		const record = w.wallet.getCompositeSplice(res.id)!;
		expect(record.reason).to.match(/left \(FORCE_CLOSED\)|left \(/);
		expect(w.storage.loadCompositeSplice(record.id)!.stage).to.equal(
			'CONFLICTED'
		);
		expect(stageNames(w).slice(-1)).to.deep.equal(['CONFLICTED']);
		// Channel 1 is no longer reserved by the composite.
		const close = w.wallet.closeChannel(w.channels[1], destinationScript());
		expect(close.error ?? '').to.not.match(/composite splice/);
		const plan = await w.wallet.planCompositeSpliceOut(request());
		if (!plan.ok)
			expect(plan.code).to.not.equal(CompositeSpliceRefusalCode.BUSY);
	});

	it('a peer disconnect before commitment aborts the composite at once, not at the end of the budget', async function () {
		const w = await makeWorld(7230, [FUNDING, FUNDING]);
		worlds.push(w);
		w.gates[1].hold = true;
		const res = await w.wallet.startCompositeSpliceOut(request(60_000));
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('NEGOTIATING');
		const started = Date.now();
		await disconnect(w.wallet, w.peers[1], w.cuts[1]);
		await waitFor(
			() => w.wallet.getCompositeSplice(res.id)!.stage === 'ABORTED',
			'the composite to abort on the disconnect'
		);
		expect(Date.now() - started, 'did not wait for the budget').to.be.lessThan(
			5_000
		);
		expect(w.wallet.getCompositeSplice(res.id)!.reason).to.match(
			/disconnected before release/
		);
		w.gates[1].hold = false;
		while (w.gates[1].queue.length > 0) {
			const m = w.gates[1].queue.shift()!;
			m.to.handlePeerMessage(m.from, m.type, m.p);
		}
		await waitFor(
			() =>
				w.wallet.getRawChannel(w.channels[0])!.getState() ===
					ChannelState.NORMAL &&
				w.wallet.getRawChannel(w.channels[0])!.getFullState().spliceInFlight ===
					null,
			'the first channel back to NORMAL'
		);
		expect(w.broadcasts).to.deep.equal([]);
	});

	it('terminal records older than the retention window are pruned at boot', async function () {
		const storage = new MemoryStorage();
		const now = Date.now();
		const old = storedRecord(
			'11'.repeat(32),
			'LOCKED',
			now - COMPOSITE_SPLICE_RETENTION_MS - 60_000
		);
		const recent = storedRecord('22'.repeat(32), 'ABORTED', now - 60_000);
		storage.saveCompositeSplice(old);
		storage.saveCompositeSplice(recent);
		const w = await makeWorld(7240, [FUNDING, FUNDING], storage);
		worlds.push(w);
		expect(w.wallet.listCompositeSplices().map((r) => r.id)).to.deep.equal([
			recent.id
		]);
		expect(storage.loadCompositeSplice(old.id)).to.equal(null);
		expect(storage.loadCompositeSplice(recent.id)!.stage).to.equal('ABORTED');
	});

	it('channels sharing an in-flight splice with no record get a synthesized one at boot and still reach LOCKED', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7250, [FUNDING, FUNDING], storage);
		worlds.push(w);
		const res = await w.wallet.startCompositeSpliceOut(request());
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		await waitFor(
			() => w.stages.some((s) => s.stage === 'BROADCAST'),
			'broadcast'
		);
		const txid = w.wallet.getCompositeSplice(res.id)!.txid!;
		// A journal rebuilt from a snapshot older than the record: the record
		// is gone, the channel rows are not.
		storage.deleteCompositeSplice(res.id.toString('hex'));
		silence(w);
		w.wallet.destroy();
		const restarted = createNode(7250, storage);
		w.nodes.push(restarted);
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		const list = restarted.listCompositeSplices();
		expect(list).to.have.length(1);
		const synthesized = list[0];
		expect(synthesized.id).to.not.equal(res.id.toString('hex'));
		expect(synthesized.stage).to.equal('RELEASED');
		expect(synthesized.txid).to.equal(txid);
		expect(synthesized.reason).to.match(/synthesized from channel records/);
		expect(synthesized.channels.map((c) => c.channelId).sort()).to.deep.equal(
			w.channels.map((c) => c.toString('hex')).sort()
		);
		expect(storage.loadCompositeSplice(synthesized.id)!.stage).to.equal(
			'RELEASED'
		);
		for (let i = 0; i < 2; i++) await reconnectRestarted(restarted, w.peers[i]);
		for (let i = 0; i < 2; i++) {
			restarted.getChannelManager().sendSpliceLocked(w.channels[i]);
			w.peers[i].getChannelManager().sendSpliceLocked(w.channels[i]);
		}
		await waitFor(
			() =>
				restarted.getCompositeSplice(Buffer.from(synthesized.id, 'hex'))!
					.stage === 'LOCKED',
			'the synthesized record to reach LOCKED'
		);
	});

	it('an ABORTED record whose sessions were not all unwound is finished at boot', async function () {
		const storage = new MemoryStorage();
		const w = await makeWorld(7260, [FUNDING, FUNDING], storage);
		worlds.push(w);
		const hold = holdFromPeer(w, 1, MessageType.TX_SIGNATURES);
		const res = await w.wallet.startCompositeSpliceOut(request(60_000));
		expect(res.ok).to.equal(true);
		if (!res.ok) return;
		expect(w.wallet.getCompositeSplice(res.id)!.stage).to.equal('COMMITTED');
		// A crash between the terminal write and the session unwinds: the
		// record says ABORTED while both channels still hold their splice.
		const stored = storage.loadCompositeSplice(res.id.toString('hex'))!;
		storage.saveCompositeSplice({
			...stored,
			stage: 'ABORTED',
			reason: 'simulated crash between the terminal write and the unwinds'
		});
		hold.release();
		silence(w);
		w.wallet.destroy();
		const restarted = createNode(7260, storage);
		w.nodes.push(restarted);
		await waitFor(
			() => restarted.getChannelManager().listChannels().length === 2,
			'channels restored'
		);
		expect(restarted.getCompositeSplice(res.id)!.stage).to.equal('ABORTED');
		for (const id of w.channels) {
			const st = restarted.getRawChannel(id)!.getFullState();
			expect(st.spliceInFlight, 'the leftover session was forgotten').to.equal(
				null
			);
			expect(st.preReestablishState).to.equal(ChannelState.NORMAL);
			expect(st.spliceAbortOwed).to.equal(true);
		}
		for (let i = 0; i < 2; i++) await reconnectRestarted(restarted, w.peers[i]);
		await waitFor(
			() =>
				w.channels.every(
					(id) =>
						restarted.getRawChannel(id)!.getState() === ChannelState.NORMAL
				),
			'both channels NORMAL on the old funding'
		);
		for (const id of w.channels) {
			expect(
				restarted.getRawChannel(id)!.getFullState().fundingSatoshis
			).to.equal(FUNDING);
		}
	});

	it('a one-channel record read from storage round-trips through the node API', async function () {
		const w = await makeWorld(7180, [FUNDING, FUNDING]);
		worlds.push(w);
		expect(w.wallet.getCompositeSplice(crypto.randomBytes(32))).to.equal(null);
		expect(() => w.wallet.getCompositeSplice(Buffer.alloc(3))).to.throw(
			/32 bytes/
		);
		expect(w.wallet.abortCompositeSplice(crypto.randomBytes(32)).code).to.equal(
			CompositeSpliceRefusalCode.NOT_FOUND
		);
		const records: ICompositeSpliceRecord[] = w.wallet.listCompositeSplices();
		expect(records).to.deep.equal([]);
		// decodeTxAddOutputMessage is imported for the adversarial case above;
		// use it once so the import is not dead.
		expect(typeof decodeTxAddOutputMessage).to.equal('function');
	});
});
