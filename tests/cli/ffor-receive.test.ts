import assert from 'assert';
import { EventEmitter } from 'events';
import crypto from 'crypto';
import { FforReceiveService } from '../../src/cli/ffor-receive';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';

const peer = '02' + '11'.repeat(32);
const other = '03' + '22'.repeat(32);
const channelId = '33'.repeat(32);
const epochId = '44'.repeat(32);
const preimage = Buffer.alloc(32, 5);
function fixture(role = 'R') {
	const node: any = new EventEmitter();
	const sent: any[] = [];
	const added: any[] = [];
	let disk: string | null = null;
	const record: any = {
		role,
		state: FforState.ACTIVE,
		remoteNodeId: Buffer.from(peer, 'hex'),
		epochId: Buffer.from(epochId, 'hex'),
		params: { maxPayments: 1 },
		paymentHashes: [crypto.createHash('sha256').update(preimage).digest()],
		knownPreimages: [null]
	};
	let durable: any = {
		...record,
		slotStates: [FforSlotState.SETTLED],
		preimages: [preimage]
	};
	node.sendCustomMessage = (p: string, subtype: number, payload: Buffer) =>
		sent.push({ peer: p, subtype, ...JSON.parse(payload.toString()) });
	node.getFforEpoch = () => record;
	node.fforAddPreimage = (_: string, p: Buffer) => {
		added.push(p);
		return { ok: true };
	};
	/** The operator's zero-conf trusted set, empty unless a cell grants it. */
	const trustedPeers = new Set<string>();
	node.getChannelManager = () => ({
		isTrustedPeer: (p: string) => trustedPeers.has(p),
		getChannelsByPeer: () => []
	});
	const storage = {
		loadWalletData: () => disk,
		saveWalletData: (_: string, v: string) => {
			disk = v;
		},
		loadChannel: () => ({ state: { ffor: durable } })
	};
	/** Every argument list the allocate path handed to openChannel. */
	const opened: unknown[][] = [];
	const host: any = {
		getNode: () => node,
		getStorage: () => storage,
		openChannel: (...args: unknown[]) => {
			opened.push(args);
			throw Error('funding failed');
		}
	};
	const service = new FforReceiveService(
		host,
		{ enabled: true },
		{
			enabled: true,
			maxChannels: 1,
			maxChannelsPerPeer: 1,
			maxChannelSats: 100000,
			maxTotalSats: 100000
		}
	);
	const response = (result: any, sender = peer) =>
		node.emit('custom-message', {
			peerPubkey: sender,
			version: 1,
			subtype: 81,
			payload: Buffer.from(
				JSON.stringify({ id: sent[sent.length - 1].id, ok: true, result })
			)
		});
	return {
		service,
		node,
		sent,
		record,
		added,
		response,
		host,
		storage,
		opened,
		trust: (p: string): Set<string> => trustedPeers.add(p),
		get durable() {
			return durable;
		},
		set durable(v) {
			durable = v;
		}
	};
}
describe('automatic receive service', () => {
	it('authenticates replies and verifies the invoice hash before saving any receipt', async () => {
		const f = fixture();
		try {
			const task = f.service.receipts(channelId);
			const result = {
				channelId,
				epochId,
				receipts: [{ k: 1, preimage: preimage.toString('hex') }]
			};
			f.response(result, other);
			assert.equal(f.added.length, 0);
			f.response(result);
			await task;
			assert.equal(f.added.length, 1);
			const invalid = f.service.receipts(channelId);
			f.response({
				...result,
				receipts: [{ k: 1, preimage: 'ff'.repeat(32) }]
			});
			await assert.rejects(invalid, /does not match/);
			assert.equal(f.added.length, 1);
		} finally {
			f.service.stop();
		}
	});
	it('does not apply receipts after the epoch changes during the query', async () => {
		const f = fixture();
		try {
			const task = f.service.receipts(channelId);
			f.record.state = FforState.CLOSED;
			f.response({
				channelId,
				epochId,
				receipts: [{ k: 1, preimage: preimage.toString('hex') }]
			});
			await assert.rejects(task, /changed/);
			assert.equal(f.added.length, 0);
		} finally {
			f.service.stop();
		}
	});
	it('only discloses durably settled receipts to the receiving peer', async () => {
		const f = fixture('S');
		try {
			const request = { op: 'receipts', channelId, epochId };
			for (const state of [FforSlotState.UNUSED, FforSlotState.SETTLING]) {
				f.durable.slotStates = [state];
				assert.deepEqual(
					(await (f.service as any).serve(peer, request)).receipts,
					[]
				);
			}
			f.durable.slotStates = [FforSlotState.SETTLED];
			await assert.rejects((f.service as any).serve(other, request), /Unknown/);
			assert.equal(
				(await (f.service as any).serve(peer, request)).receipts.length,
				1
			);
			assert.equal(f.record.state, FforState.ACTIVE);
		} finally {
			f.service.stop();
		}
	});
	it('reserves funding limits before opening and preserves them across restarts', async () => {
		const f = fixture('S');
		try {
			const request = {
				op: 'allocate',
				allocationId: 'aa'.repeat(16),
				amountSats: 10000
			};
			await assert.rejects(
				(f.service as any).serve(peer, request),
				/funding failed/
			);
			f.service.stop();
			const reopened = new FforReceiveService(
				f.host,
				{ enabled: true },
				{
					enabled: true,
					maxChannels: 1,
					maxChannelsPerPeer: 1,
					maxChannelSats: 100000,
					maxTotalSats: 100000
				}
			);
			try {
				await assert.rejects(
					(reopened as any).serve(peer, request),
					/still being prepared/
				);
				await assert.rejects(
					(reopened as any).serve(other, {
						...request,
						allocationId: 'bb'.repeat(16)
					}),
					/no receive capacity/
				);
			} finally {
				reopened.stop();
			}
		} finally {
			f.service.stop();
		}
	});
	// The allocate open used to pass a hardcoded trusted=true and grant itself
	// the matching authorization, so a provider with receive funding enabled
	// proposed a zero_conf channel type to every client, past the operator's
	// trusted set. A plain daemon on the far side refuses that outright.
	it('proposes zero-conf on an allocate open only for a peer the operator trusts', async () => {
		const request = {
			op: 'allocate',
			allocationId: 'cc'.repeat(16),
			amountSats: 10000
		};
		type Allocator = { serve(peer: string, body: unknown): Promise<unknown> };
		const untrusted = fixture('S');
		try {
			await assert.rejects(
				(untrusted.service as unknown as Allocator).serve(peer, request),
				/funding failed/
			);
			assert.deepEqual(untrusted.opened, [[peer, 60000, 0, 2, false, false]]);
		} finally {
			untrusted.service.stop();
		}
		const trusted = fixture('S');
		trusted.trust(peer);
		try {
			await assert.rejects(
				(trusted.service as unknown as Allocator).serve(peer, request),
				/funding failed/
			);
			assert.deepEqual(trusted.opened, [[peer, 60000, 0, 2, false, true]]);
		} finally {
			trusted.service.stop();
		}
	});
	it('stopping cancels pending queries', async () => {
		const f = fixture();
		const p = f.service.request(peer, { op: 'quote' });
		f.service.stop();
		await assert.rejects(p, /stopped/);
	});
});
