import { encodeTxAbortMessage } from '../../src/lightning/message/interactive-tx';
import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	AssetSpliceTransport,
	type AssetSpliceHost
} from '../../src/lightning/channel/asset-splice-transport';
import { MessageType as M } from '../../src/lightning/message/types';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../src/lightning/message/custom';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';

const limits = {
	channelReserveSats: '1000',
	htlcMinimumMsat: '1',
	maxHtlcValueInFlightMsat: '1000000',
	maxAcceptedHtlcs: 8
};

describe('Asset splice peer session replay', function () {
	this.timeout(60000);
	let dir: string;
	let setup: ReturnType<typeof setupAssetSpliceProofs>;
	const transports: AssetSpliceTransport[] = [];

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-splice-replay-'));
		setup = setupAssetSpliceProofs(dir, { local: limits, remote: limits });
		setup.fundOpening();
		const ready = setup.devices.map(({ store, party }) =>
			store.finalOpeningChannelReady(setup.id, party.root)
		);
		setup.devices.forEach(({ store }, i) =>
			store.rememberFinalPeerChannelReady(setup.id, ready[1 - i])
		);
	});
	afterEach(() => {
		for (const t of transports.splice(0)) t.destroy();
		for (const d of setup.devices) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('consumes the terminal abort acknowledgement only for the last retired attempt', async () => {
		const d = setup.devices[0],
			peer = setup.devices[1].party.binding.nodeId,
			id = setup.id;
		const host = {
			spliceContribution: () => 0n,
			abandonSplice: async () => undefined
		} as unknown as AssetSpliceHost;
		const sent: number[] = [],
			reasons: string[] = [];
		const t = new AssetSpliceTransport(
			{ storage: d.store, root: d.party.root },
			host,
			(p, i) => p === peer && i === id,
			() => true,
			() => 120,
			(_p, type) => sent.push(type),
			async () => 'unspent',
			() => undefined,
			() => undefined,
			(_id, e) => reasons.push(e)
		);
		transports.push(t);
		const ack = encodeTxAbortMessage({
			channelId: Buffer.from(id, 'hex'),
			data: Buffer.from('Splice abandoned')
		});
		expect(t.handle(peer, M.TX_ABORT, ack)).to.equal(false);
		await t.start(id, { fundingFeeratePerkw: 1000, minimumDepth: 3 });
		expect(t.handle(peer, M.TX_ABORT, ack)).to.equal(true);
		for (let i = 0; i < 50 && !sent.includes(M.TX_ABORT); i++)
			await new Promise<void>((resolve) => setImmediate(resolve));
		expect(sent).to.include(M.TX_ABORT);
		expect(t.handle(peer, M.TX_ABORT, ack)).to.equal(true);
		expect(
			t.handle(
				peer,
				M.TX_ABORT,
				encodeTxAbortMessage({
					channelId: Buffer.from(id, 'hex'),
					data: Buffer.from('unrelated')
				})
			)
		).to.equal(false);
		expect(reasons).to.deep.equal([]);
	});

	for (const beforeResume of [false, true])
		it(
			'delivers the first replayed proof frame ' +
				(beforeResume ? 'before' : 'after') +
				' the channel resumes in the same socket read',
			async () => {
				const sent: { from: number; type: number; wire: Buffer }[] = [];
				const invalid: string[] = [];
				const waiting = new Promise<never>(() => undefined);
				const nodes = setup.devices.map(({ store, party }, i) => {
					const host = {
						proposeSplice: async () => Buffer.from('retained-local-offer-' + i),
						spliceContribution: () => (i ? 0n : 500n),
						describeSplice: () => waiting
					} as unknown as AssetSpliceHost;
					const t = new AssetSpliceTransport(
						{ storage: store, root: party.root },
						host,
						(peer, id) =>
							peer === setup.devices[1 - i].party.binding.nodeId &&
							id === setup.id,
						() => true,
						() => 120,
						(_peer, type, wire) =>
							sent.push({ from: i, type, wire: Buffer.from(wire) }),
						async () => 'unspent',
						() => undefined,
						() => undefined,
						(_id, reason) => invalid.push(reason)
					);
					transports.push(t);
					return t;
				});
				const deliver = (from: number, type: number, wire: Buffer) => {
					const peer = setup.devices[from].party.binding.nodeId;
					if (type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
						const { subtype, payload } = decodeCustomMessage(wire);
						nodes[1 - from].custom(peer, subtype, payload);
					} else {
						expect(nodes[1 - from].handle(peer, type, wire)).to.equal(true);
					}
				};
				const tick = () =>
					new Promise<void>((resolve) => setImmediate(resolve));
				async function next(from: number, type: number) {
					for (let i = 0; i < 10; i++) {
						const n = sent.findIndex((x) => x.from === from && x.type === type);
						if (n !== -1) return sent.splice(n, 1)[0].wire;
						await tick();
					}
					expect(invalid).to.deep.equal([]);
					throw Error('Missing wire ' + type);
				}
				await nodes[0].start(setup.id, {
					fundingFeeratePerkw: 253,
					minimumDepth: 3
				});
				deliver(0, M.STFU, await next(0, M.STFU));
				deliver(1, M.STFU, await next(1, M.STFU));
				deliver(0, M.SPLICE, await next(0, M.SPLICE));
				deliver(1, M.SPLICE_ACK, await next(1, M.SPLICE_ACK));
				await next(0, BEIGNET_CUSTOM_MESSAGE_TYPE);
				await next(1, BEIGNET_CUSTOM_MESSAGE_TYPE);
				for (const i of [0, 1])
					nodes[i].disconnected(setup.devices[1 - i].party.binding.nodeId);
				nodes[1].resume(setup.devices[0].party.binding.nodeId, setup.id);
				const peerReplay = await next(1, BEIGNET_CUSTOM_MESSAGE_TYPE);
				const peer = setup.devices[1].party.binding.nodeId;
				nodes[0].reconnected(peer);
				if (beforeResume) deliver(1, BEIGNET_CUSTOM_MESSAGE_TYPE, peerReplay);
				nodes[0].resume(peer, setup.id);
				if (!beforeResume) deliver(1, BEIGNET_CUSTOM_MESSAGE_TYPE, peerReplay);
				await tick();
				const history = setup.devices[0].store.readAssetSpliceJournal<{
					kind: string;
					local?: boolean;
					field?: string;
					bytes?: string;
				}>(setup.id).records;
				const seen = history.find(
					(e) =>
						e.kind === 'exchange' && e.local === false && e.field === 'layout'
				);
				expect(seen?.bytes).to.equal(
					Buffer.from('retained-local-offer-1').toString('hex')
				);
				expect(invalid).to.deep.equal([]);
			}
		);
});
