import { expect } from 'chai';
import { EventEmitter } from 'events';
import type { Channel } from '../../src/lightning/channel/channel';
import {
	ChainWatcher,
	IChainBackend,
	IChainWatcherChannelManager
} from '../../src/lightning/chain/chain-watcher';

const settle = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));
async function fixture(
	lookup: NonNullable<IChainBackend['getTransactionMerkleProof']>
) {
	const channelId = Buffer.alloc(32, 7),
		txid = Buffer.alloc(32, 8).toString('hex');
	class Manager extends EventEmitter implements IChainWatcherChannelManager {
		listChannels(): Channel[] {
			return [
				{
					getFullState: () => ({ channelId, announceChannel: false })
				} as Channel
			];
		}
		handleNewBlock() {}
		handleFundingConfirmed() {}
		handleFundingSpent() {}
		handleFundingSpendAbsent() {
			return false;
		}
		handleOutputSpent() {}
		handleOutputUnspent() {}
	}
	const manager = new Manager();
	let header: (height: number) => void = () => undefined;
	const backend: IChainBackend = {
		subscribeToHeaders: async (callback) => {
			header = callback;
			callback(100);
		},
		subscribeToScriptHash: async () => undefined,
		getScriptHashHistory: async () => [{ txid, height: 100 }],
		getTransaction: async () => Buffer.alloc(0),
		broadcastTransaction: async () => txid,
		getTransactionMerkleProof: lookup
	};
	const watcher = new ChainWatcher({ backend, channelManager: manager });
	const positions: unknown[][] = [],
		announcements: unknown[][] = [],
		errors: unknown[] = [];
	watcher.on('funding:position', (...args) => positions.push(args));
	watcher.on('announcement:depth', (...args) => announcements.push(args));
	watcher.on('error', (error) => errors.push(error));
	await watcher.start();
	const watch = () =>
		watcher.watchFundingOutput(
			channelId,
			txid,
			0,
			3,
			Buffer.from('0014' + '22'.repeat(20), 'hex')
		);
	return {
		watcher,
		backend,
		positions,
		announcements,
		errors,
		channelId,
		txid,
		watch,
		block: (height: number) => header(height)
	};
}

describe('Verified funding position for private routing', () => {
	it('reports the first confirmed position without lowering public announcement depth', async () => {
		const env = await fixture(async () => ({ blockHeight: 100, txIndex: 7 }));
		try {
			await env.watch();
			await settle();
			expect(env.positions).to.deep.equal([[env.channelId, env.txid, 100, 7]]);
			expect(env.announcements).to.have.length(0);
			env.block(102);
			await settle();
			env.block(105);
			await settle();
			expect(env.announcements).to.have.length(1);
			expect(env.positions).to.have.length(1);
		} finally {
			env.watcher.stop();
		}
	});
	it('retries a failed lookup and never invents an index', async () => {
		let calls = 0;
		const env = await fixture(async () => {
			if (calls++ === 0) throw new Error('Position unavailable');
			return { blockHeight: 100, txIndex: 9 };
		});
		try {
			await env.watch();
			await settle();
			expect(env.positions).to.have.length(0);
			env.block(101);
			await settle();
			expect(env.positions).to.deep.equal([[env.channelId, env.txid, 100, 9]]);
			expect(env.errors).to.have.length(1);
		} finally {
			env.watcher.stop();
		}
	});
	it('rejects a mismatched block height and a malformed transaction index', async () => {
		const responses = [
			{ blockHeight: 99, txIndex: 7 },
			{ blockHeight: 100, txIndex: -1 },
			{ blockHeight: 100, txIndex: 0x1000000 },
			{ blockHeight: 100, txIndex: 3 }
		];
		const env = await fixture(async () => responses.shift()!);
		try {
			await env.watch();
			await settle();
			env.block(101);
			await settle();
			env.block(102);
			await settle();
			expect(env.positions).to.have.length(0);
			env.block(103);
			await settle();
			expect(env.positions).to.deep.equal([[env.channelId, env.txid, 100, 3]]);
		} finally {
			env.watcher.stop();
		}
	});
	it('drops a stale lookup after watch replacement and after stop', async () => {
		let release: (value: {
				blockHeight: number;
				txIndex: number;
			}) => void = () => undefined,
			calls = 0;
		const env = await fixture(async () =>
			calls++ === 0
				? new Promise((resolve) => {
						release = resolve;
				  })
				: { blockHeight: 100, txIndex: 5 }
		);
		try {
			await env.watch();
			await settle();
			await env.watch();
			await settle();
			release({ blockHeight: 100, txIndex: 99 });
			await settle();
			expect(env.positions).to.deep.equal([[env.channelId, env.txid, 100, 5]]);
			const watched = [...env.watcher['watchedFundings'].values()][0];
			env.watcher['reportFundingUnseen'](watched);
			env.backend.getTransactionMerkleProof = async () =>
				new Promise((resolve) => {
					release = resolve;
				});
			env.watcher['reportFundingSeen'](watched, env.txid, 100);
			await settle();
			env.watcher.stop();
			release({ blockHeight: 100, txIndex: 11 });
			await settle();
			expect(env.positions).to.have.length(1);
		} finally {
			env.watcher.stop();
		}
	});
});
