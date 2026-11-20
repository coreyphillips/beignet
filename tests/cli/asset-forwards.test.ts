/**
 * Issue #2098, step 7: what the daemon shows of a forward with an asset
 * leg, and the gate it sets on such forwards.
 *
 * The daemon lists such a forward (GET /forwards) with its marks as decimal
 * strings, keeps it out of the bitcoin totals of its summary and counts it
 * in their `auxiliary` beside them, and relays its htlc:forwarded and
 * htlc:forward-refused events marked. On every node that runs asset
 * channels it sets the node's forward gate (setAuxiliaryForwardGate), which
 * refuses a forward with an asset leg while the node drains, so a drain
 * before a stop or a downgrade starts no new one. An ordinary forward is
 * shown, relayed and let through exactly as before.
 *
 * Offline suite, like asset-payment-limits.test.ts: no chain and no
 * channel. Rows are written to the node's storage as the engine writes
 * them, and events raised as the engine raises them.
 */

import { expect } from 'chai';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	EXTENSION_API_VERSION,
	IBeignetExtension
} from '../../src/cli/extension';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { referenceProvider } from '../lightning/helpers/auxiliary-pair';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const BOOT = {
	mnemonic: MNEMONIC,
	network: 'regtest' as const,
	logLevel: 'silent' as const,
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

/** An extension that supplies the node's asset channels, and nothing else. */
const assets = (): IBeignetExtension => ({
	id: 'assets',
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach: () => ({
		auxiliaryChannels: {
			provider: referenceProvider(),
			resolveIncoming: (): undefined => undefined
		}
	})
});

type Engine = {
	auxiliaryForwardGate?: (forward: unknown) => unknown;
	emit: (event: string, data: unknown) => boolean;
};

const IN = Buffer.alloc(32, 0x11);
const OUT = Buffer.alloc(32, 0x22);
const NEXT = Buffer.from('0102030405060708', 'hex');

/** A forward with an asset leg as the gate is given it. */
const GATED = {
	paymentHash: Buffer.alloc(32, 0x33),
	shortChannelId: NEXT,
	incoming: {
		channelId: IN,
		peerPubkey: '02'.padEnd(66, '1'),
		htlcId: 0n,
		wireAmountMsat: 354_000n,
		auxiliaryAmount: 5_010n,
		valueMsat: 5_010_000n,
		auxiliaryChannel: true
	},
	outgoing: {
		channelId: OUT,
		peerPubkey: '03'.padEnd(66, '2'),
		wireAmountMsat: 354_000n,
		amountMsat: 5_000_000n,
		auxiliaryChannel: true
	},
	feeMsat: 10_000n
};

/** The keys of an ordinary forward's row and event, as before this step. */
const ROW_KEYS = [
	'amountInMsat',
	'amountOutMsat',
	'feeMsat',
	'id',
	'inChannelId',
	'inScid',
	'outChannelId',
	'outScid',
	'settledAt'
];
const EVENT_KEYS = [
	'amountInMsat',
	'amountOutMsat',
	'feeMsat',
	'inChannelId',
	'outChannelId'
];

describe('The daemon shows a forward with an asset leg, and stops new ones while it drains (#2098, step 7)', function () {
	this.timeout(60_000);

	let node: BeignetNode;
	let storage: MemoryStorage;
	let others: BeignetNode[];

	const engine = (of: BeignetNode = node): Engine =>
		of.getNode() as unknown as Engine;

	beforeEach(async () => {
		others = [];
		storage = new MemoryStorage();
		node = await BeignetNode.create({
			...BOOT,
			storage,
			extensions: [assets()]
		});
	});

	afterEach(async () => {
		await node?.destroy();
		for (const other of others) await other.destroy();
	});

	it('sets the forward gate only on a node that runs asset channels', async () => {
		expect(engine().auxiliaryForwardGate).to.be.a('function');
		const plain = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage()
		});
		others.push(plain);
		expect(engine(plain).auxiliaryForwardGate).to.equal(undefined);
	});

	it('refuses a forward with an asset leg while the node drains, by SERVICE_DRAINING, and lets it through otherwise', () => {
		const gate = engine().auxiliaryForwardGate!;
		expect(gate(GATED)).to.equal(undefined);
		node.setDraining(true);
		const refusal = gate(GATED) as { reason: string; message: string };
		expect(refusal.reason).to.equal('SERVICE_DRAINING');
		expect(refusal.message).to.match(/draining/);
		// No em dash in the sentence: the character is built, not written.
		expect(refusal.message).to.not.contain(String.fromCharCode(0x2014));
		node.setDraining(false);
		expect(gate(GATED)).to.equal(undefined);
	});

	// Found by the independent review of this step: the drain of POST /stop
	// waits only while hasPendingPayments() is true, and a forward with an
	// asset leg in flight did not count, so a drained stop went ahead with
	// one in flight.
	it('a drained stop waits while a forward with an asset leg is in flight, or an end of one waits for its host', () => {
		const channel = Buffer.alloc(32, 0x55);
		let info: {
			forwardsInFlight?: number;
			undeliveredForwardLegEnds?: number;
		} = { forwardsInFlight: 1 };
		const stub = (of: BeignetNode): void => {
			const inner = of.getNode() as unknown as {
				listChannels: () => unknown[];
				getAuxiliaryChannelInfo: (id: Buffer) => unknown;
			};
			const listed = inner.listChannels.bind(inner);
			inner.listChannels = (): unknown[] => [
				...listed(),
				{ channelId: channel, state: 'NORMAL', auxiliary: true }
			];
			inner.getAuxiliaryChannelInfo = (id: Buffer): unknown =>
				id.equals(channel)
					? { channelId: channel, ...info, htlcs: [] }
					: undefined;
		};
		stub(node);
		node.setDraining(true);
		expect(node.hasPendingPayments(), 'a forward in flight').to.equal(true);
		info = { undeliveredForwardLegEnds: 2 };
		expect(node.hasPendingPayments(), 'an end not taken').to.equal(true);
		info = {};
		expect(node.hasPendingPayments(), 'neither').to.equal(false);
	});

	it('a node without asset channels waits for none', async () => {
		const plain = await BeignetNode.create({
			...BOOT,
			storage: new MemoryStorage()
		});
		others.push(plain);
		const inner = plain.getNode() as unknown as {
			listChannels: () => unknown[];
			getAuxiliaryChannelInfo: (id: Buffer) => unknown;
		};
		inner.listChannels = (): unknown[] => [
			{ channelId: OUT, state: 'NORMAL', auxiliary: true }
		];
		inner.getAuxiliaryChannelInfo = (): unknown => ({ forwardsInFlight: 1 });
		expect(plain.hasPendingPayments()).to.equal(false);
	});

	it('lists a forward with an asset leg with its marks as decimal strings, and an ordinary one as before', () => {
		storage.saveForwardingEvent({
			settledAt: 100,
			inChannelId: IN.toString('hex'),
			outChannelId: OUT.toString('hex'),
			amountInMsat: 1_005n,
			amountOutMsat: 1_000n,
			feeMsat: 5n
		});
		storage.saveForwardingEvent({
			settledAt: 200,
			inChannelId: IN.toString('hex'),
			outChannelId: OUT.toString('hex'),
			amountInMsat: 5_010_000n,
			amountOutMsat: 5_000_000n,
			feeMsat: 10_000n,
			auxiliary: true,
			inAuxiliaryAmount: 5_010n,
			inWireAmountMsat: 354_000n,
			outAuxiliaryAmount: 18_446_744_073_709_551_615n,
			outWireAmountMsat: 354_000n,
			nextHopScid: NEXT.toString('hex')
		});
		const [marked, ordinary] = node.listForwards();
		expect(marked).to.deep.include({
			settledAt: 200,
			amountInMsat: '5010000',
			amountOutMsat: '5000000',
			feeMsat: '10000',
			auxiliary: true,
			inAuxiliaryAmount: '5010',
			inWireAmountMsat: '354000',
			outAuxiliaryAmount: '18446744073709551615',
			outWireAmountMsat: '354000',
			nextHopScid: NEXT.toString('hex')
		});
		expect(Object.keys(ordinary).sort()).to.deep.equal(ROW_KEYS);
		expect(ordinary).to.deep.include({
			amountInMsat: '1005',
			amountOutMsat: '1000',
			feeMsat: '5'
		});
		expect(node.getForwardingSummary()).to.deep.equal({
			count: 1,
			volumeOutMsat: '1000',
			feesEarnedMsat: '5',
			auxiliary: {
				count: 1,
				volumeOutMsat: '5000000',
				feesEarnedMsat: '10000'
			}
		});
		expect(node.getForwardingSummary(150)).to.deep.equal({
			count: 0,
			volumeOutMsat: '0',
			feesEarnedMsat: '0',
			auxiliary: {
				count: 1,
				volumeOutMsat: '5000000',
				feesEarnedMsat: '10000'
			}
		});
		expect(Object.keys(node.getForwardingSummary(300)).sort()).to.deep.equal([
			'count',
			'feesEarnedMsat',
			'volumeOutMsat'
		]);
	});

	it('relays htlc:forwarded of a forward with an asset leg with its marks as strings, and an ordinary one as before', () => {
		const seen: Array<Record<string, unknown>> = [];
		node.on('htlc:forwarded', (event: Record<string, unknown>) => {
			seen.push(event);
		});
		engine().emit('htlc:forwarded', {
			inChannelId: IN,
			outChannelId: OUT,
			amountInMsat: 1_005n,
			amountOutMsat: 1_000n,
			feeMsat: 5n
		});
		engine().emit('htlc:forwarded', {
			inChannelId: IN,
			outChannelId: OUT,
			amountInMsat: 5_010_000n,
			amountOutMsat: 5_000_000n,
			feeMsat: 10_000n,
			auxiliary: true,
			inAuxiliaryAmount: 5_010n,
			inWireAmountMsat: 354_000n,
			nextHopScid: NEXT
		});
		expect(seen).to.have.length(2);
		expect(Object.keys(seen[0]).sort()).to.deep.equal(EVENT_KEYS);
		expect(seen[1]).to.deep.equal({
			inChannelId: IN.toString('hex'),
			outChannelId: OUT.toString('hex'),
			amountInMsat: '5010000',
			amountOutMsat: '5000000',
			feeMsat: '10000',
			auxiliary: true,
			inAuxiliaryAmount: '5010',
			inWireAmountMsat: '354000',
			nextHopScid: NEXT.toString('hex')
		});
	});

	it('relays htlc:forward-refused of a forward with an asset leg marked, and an ordinary one as before', () => {
		const seen: Array<Record<string, unknown>> = [];
		node.on('htlc:forward-refused', (event: Record<string, unknown>) => {
			seen.push(event);
		});
		const refused = {
			inChannelId: IN,
			outChannelId: OUT,
			amountMsat: 5_000_000n,
			paymentHash: Buffer.alloc(32, 0x44),
			reason: 'insufficient asset balance'
		};
		engine().emit('htlc:forward-refused', { ...refused, auxiliary: true });
		engine().emit('htlc:forward-refused', refused);
		expect(seen).to.have.length(2);
		expect(seen[0].auxiliary).to.equal(true);
		expect(Object.keys(seen[1])).to.not.include('auxiliary');
	});
});
