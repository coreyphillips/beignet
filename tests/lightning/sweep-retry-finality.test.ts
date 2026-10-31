import {
	serializeChainMonitorState,
	deserializeChainMonitorState
} from '../../src/lightning/storage/serialization';
import { expect } from 'chai';
import { EventEmitter } from 'events';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChainWatcher,
	IChainBackend,
	IChainWatcherChannelManager
} from '../../src/lightning/chain/chain-watcher';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainActionType,
	IRREVOCABLE_DEPTH,
	ITrackedOutput,
	MonitorState,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { setupNormalChannels } from './helpers/revoked-commitment-fixture';

const settle = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));
const fixture = async (twoInputs = false) => {
	const { opener, openerPrivkeys } = setupNormalChannels();
	const channelId = opener.getChannelId()!;
	const parentTx = new bitcoin.Transaction();
	parentTx.addInput(Buffer.alloc(32, 0x74), 0);
	parentTx.addOutput(Buffer.from('0014' + 'bb'.repeat(20), 'hex'), 50000);
	parentTx.addOutput(Buffer.from('0014' + 'bb'.repeat(20), 'hex'), 50000);
	const parent = parentTx.getId();
	const sweep = (value: number, indexes: number[]): bitcoin.Transaction => {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		for (const index of indexes)
			tx.addInput(Buffer.from(parent, 'hex').reverse(), index, 0xfffffffd);
		tx.addOutput(Buffer.from('0014' + 'aa'.repeat(20), 'hex'), value);
		return tx;
	};
	const winner = sweep(49000, [0]);
	const obsolete = sweep(48000, twoInputs ? [0, 1] : [0]);
	const output: ITrackedOutput = {
		txid: parent,
		outputIndex: 0,
		amount: 50000n,
		outputType: OutputType.TO_LOCAL,
		status: OutputStatus.SPEND_BROADCAST,
		confirmationHeight: 90,
		broadcastHeight: 100,
		sweepTxHex: obsolete.toHex(),
		auxiliaryData: Buffer.from('new'),
		auxiliarySweepAttempts: {
			[winner.getId()]: {
				transaction: winner.toHex(),
				auxiliaryData: Buffer.from('original')
			},
			[obsolete.getId()]: {
				transaction: obsolete.toHex(),
				auxiliaryData: Buffer.from('new')
			}
		}
	};
	const untouched: ITrackedOutput = {
		txid: parent,
		outputIndex: 1,
		amount: 50000n,
		outputType: OutputType.TO_LOCAL,
		status: OutputStatus.UNCONFIRMED,
		confirmationHeight: 0
	};
	const monitor = ChainMonitor.restore(
		{
			monitorState: MonitorState.RESOLVING,
			commitmentBroadcast: null,
			trackedOutputs: twoInputs ? [output, untouched] : [output],
			currentBlockHeight: 100
		},
		opener.getFullState(),
		Buffer.alloc(22),
		1,
		openerPrivkeys[1],
		openerPrivkeys[2]
	);
	class Manager extends EventEmitter implements IChainWatcherChannelManager {
		listChannels() {
			return [];
		}
		getMonitor() {
			return monitor;
		}
		getMonitors() {
			return new Map([[channelId.toString('hex'), monitor]]);
		}
		handleNewBlock(height: number) {
			for (const action of monitor.handleNewBlock(height))
				if (action.type === ChainActionType.OUTPUT_RESOLVED)
					this.emit(
						'output:resolved',
						action.txid,
						action.outputIndex,
						channelId,
						action.outputType,
						action.paymentHash,
						action.htlcId
					);
		}
		handleFundingConfirmed() {}
		handleFundingSpent() {}
		handleFundingSpendAbsent() {
			return false;
		}
		handleOutputSpent(
			txid: string,
			index: number,
			tx: bitcoin.Transaction,
			height: number
		) {
			monitor.handleOutputSpent(txid, index, tx, height);
		}
		handleOutputUnspent(txid: string, index: number) {
			monitor.handleSpendUnconfirmed(txid, index);
		}
	}
	const manager = new Manager();
	let header: (height: number) => void = () => undefined;
	const sent: string[] = [],
		failures: Error[] = [],
		permanent: Error[] = [];
	const backend: IChainBackend = {
		subscribeToHeaders: async (listener) => {
			header = listener;
		},
		subscribeToScriptHash: async () => undefined,
		getScriptHashHistory: async () => [],
		getTransaction: async () => {
			throw new Error('No watched fixture transaction');
		},
		broadcastTransaction: async (raw) => {
			sent.push(bitcoin.Transaction.fromHex(raw).getId());
			throw new Error('bad-txns-inputs-missingorspent');
		}
	};
	const watcher = new ChainWatcher({ backend, channelManager: manager });
	watcher.on('broadcast:failure', (error) => failures.push(error));
	watcher.on('broadcast:permanent_failure', (error) => permanent.push(error));
	await watcher.start();
	return {
		manager,
		monitor,
		watcher,
		backend,
		sent,
		failures,
		permanent,
		winner,
		obsolete,
		parent,
		parentTx,
		channel: opener,
		channelId,
		block: (height: number) => header(height),
		send: (tx = obsolete) => manager.emit('broadcast:tx', tx.toBuffer()),
		confirm: (height = 100) =>
			monitor.handleOutputSpent(parent, 0, winner, height),
		output: () => monitor.getFullState().trackedOutputs[0],
		fresh: () => sweep(47000, [1])
	};
};

describe('Confirmed asset sweep retry retirement', () => {
	it('retires a conflicting queued attempt at irrevocable depth without a permanent failure', async () => {
		const env = await fixture();
		try {
			env.send();
			await settle();
			expect(env.failures).to.have.length(1);
			env.confirm();
			env.block(100 + IRREVOCABLE_DEPTH);
			await settle();
			for (let height = 120; height < 140; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(1);
			expect(env.permanent).to.have.length(0);
			expect(env.output().status).to.equal(OutputStatus.IRREVOCABLY_RESOLVED);
		} finally {
			env.watcher.stop();
		}
	});
	it('refuses an archived conflicting attempt submitted after the finality event', async () => {
		const env = await fixture();
		try {
			env.confirm();
			env.block(100 + IRREVOCABLE_DEPTH);
			env.send();
			await settle();
			expect(env.sent).to.have.length(0);
			expect(env.failures).to.have.length(0);
		} finally {
			env.watcher.stop();
		}
	});

	it('does not requeue a delayed backend rejection after the original attempt becomes final', async () => {
		const env = await fixture();
		try {
			let reject: (error: Error) => void = () => undefined;
			env.backend.broadcastTransaction = async (raw) => {
				env.sent.push(bitcoin.Transaction.fromHex(raw).getId());
				return new Promise<string>((_resolve, fail) => {
					reject = fail;
				});
			};
			env.send();
			await settle();
			env.confirm();
			env.block(100 + IRREVOCABLE_DEPTH);
			reject(new Error('conflicting sweep already mined'));
			await settle();
			for (let height = 120; height < 140; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(1);
			expect(env.failures).to.have.length(0);
			expect(env.permanent).to.have.length(0);
		} finally {
			env.watcher.stop();
		}
	});
	it('retires an in-flight retry before a delayed rejection can requeue it', async () => {
		const env = await fixture();
		try {
			env.send();
			await settle();
			let reject: (error: Error) => void = () => undefined;
			env.backend.broadcastTransaction = async (raw) => {
				env.sent.push(bitcoin.Transaction.fromHex(raw).getId());
				return new Promise<string>((_resolve, fail) => {
					reject = fail;
				});
			};
			env.block(101);
			env.confirm();
			env.block(100 + IRREVOCABLE_DEPTH);
			reject(new Error('older sweep confirmed'));
			await settle();
			for (let height = 120; height < 140; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(2);
			expect(env.permanent).to.have.length(0);
		} finally {
			env.watcher.stop();
		}
	});

	for (const depth of [0])
		it(`preserves retry exhaustion while winner depth is ${depth}`, async () => {
			const env = await fixture();
			try {
				env.send();
				await settle();
				env.confirm(depth === 0 ? 0 : 100);
				for (let attempt = 0; attempt < 14; attempt++) {
					env.block(depth === 0 ? 100 : 101);
					await settle();
				}
				expect(env.sent).to.have.length(13);
				expect(env.permanent).to.have.length(1);
			} finally {
				env.watcher.stop();
			}
		});
	it('pauses a confirmed conflict below finality and resumes its remaining retry budget after reorg', async () => {
		const env = await fixture(true);
		try {
			env.send();
			await settle();
			env.confirm();
			for (let height = 101; height < 125; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(1);
			expect(env.permanent).to.have.length(0);
			expect(env.output().status).to.equal(OutputStatus.SPEND_CONFIRMED);
			expect(env.monitor.getFullState().trackedOutputs[1].status).to.equal(
				OutputStatus.UNCONFIRMED
			);
			env.send(env.fresh());
			await settle();
			expect(env.sent).to.include(env.fresh().getId());
			env.monitor.handleSpendUnconfirmed(env.parent, 0);
			env.block(125);
			await settle();
			expect(
				env.sent.filter((id) => id === env.obsolete.getId())
			).to.have.length(2);
			for (let height = 126; height < 140; height++) {
				env.block(height);
				await settle();
			}
			expect(
				env.sent.filter((id) => id === env.obsolete.getId())
			).to.have.length(13);
			expect(
				env.permanent.some((error) =>
					error.message.includes(env.obsolete.getId())
				)
			).to.equal(true);
		} finally {
			env.watcher.stop();
		}
	});
	it('holds a newly submitted confirmed conflict and a delayed refusal without emitting failure', async () => {
		const env = await fixture();
		try {
			let reject: (error: Error) => void = () => undefined;
			env.backend.broadcastTransaction = async (raw) => {
				env.sent.push(bitcoin.Transaction.fromHex(raw).getId());
				return new Promise<string>((_resolve, fail) => {
					reject = fail;
				});
			};
			env.send();
			await settle();
			env.confirm();
			reject(new Error('competing sweep confirmed'));
			await settle();
			env.send();
			await settle();
			expect(env.sent).to.have.length(1);
			expect(env.failures).to.have.length(0);
			env.block(100 + IRREVOCABLE_DEPTH);
			await settle();
			expect(env.permanent).to.have.length(0);
		} finally {
			env.watcher.stop();
		}
	});
	it('does not pause a confirmation that still requires live re-verification', async () => {
		const env = await fixture();
		try {
			env.send();
			await settle();
			env.confirm();
			env.output().spendReverifyPending = true;
			for (let height = 101; height < 115; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(13);
			expect(env.permanent).to.have.length(1);
		} finally {
			env.watcher.stop();
		}
	});
	it('discovers an external confirmed remedy before broadcasting and resumes after its reorg', async () => {
		const env = await fixture();
		try {
			env.channel['_state'].auxiliaryState = {
				channelData: Buffer.alloc(0),
				localBalance: 0n,
				remoteBalance: 0n,
				localCommitments: new Map(),
				remoteCommitments: new Map()
			};
			delete env.output().auxiliarySweepAttempts![env.winner.getId()];
			env.backend.getTransaction = async (id) => {
				if (id === env.parent) return env.parentTx.toBuffer();
				if (id === env.winner.getId()) return env.winner.toBuffer();
				throw new Error('Unexpected transaction');
			};
			env.backend.getScriptHashHistory = async () => [
				{ txid: env.parent, height: 90 },
				{ txid: env.winner.getId(), height: 100 }
			];
			env.block(101);
			env.send();
			await settle();
			expect(env.sent).to.have.length(0);
			expect(env.failures).to.have.length(0);
			expect(env.output().resolutionTxHex).to.equal(env.winner.toHex());
			expect(
				deserializeChainMonitorState(
					serializeChainMonitorState(env.monitor.getFullState())
				).trackedOutputs[0].resolutionTxHex
			).to.equal(env.winner.toHex());
			expect(env.output().status).to.equal(OutputStatus.SPEND_CONFIRMED);
			env.backend.getScriptHashHistory = async () => [
				{ txid: env.parent, height: 90 }
			];
			await env.watcher['checkOutputSpend'](`${env.parent}:0`);
			expect(env.output().resolutionTxHex).to.equal(undefined);
			env.block(102);
			await settle();
			expect(env.sent).to.deep.equal([env.obsolete.getId()]);
			expect(env.permanent).to.have.length(0);
		} finally {
			env.watcher.stop();
		}
	});
	it('requires the exact retained winning transaction before suppressing a failure', async () => {
		const env = await fixture();
		try {
			env.send();
			await settle();
			env.confirm();
			env.output().auxiliarySweepAttempts![env.winner.getId()].transaction =
				env.obsolete.toHex();
			for (let height = 120; height < 135; height++) {
				env.block(height);
				await settle();
			}
			expect(env.sent).to.have.length(13);
			expect(env.permanent).to.have.length(1);
		} finally {
			env.watcher.stop();
		}
	});
	it('keeps other inputs unresolved and allows a fresh sweep and reorg resubmission', async () => {
		const env = await fixture(true);
		try {
			env.send();
			await settle();
			env.confirm();
			env.block(100 + IRREVOCABLE_DEPTH);
			await settle();
			expect(env.monitor.getFullState().trackedOutputs[1].status).to.equal(
				OutputStatus.UNCONFIRMED
			);
			const fresh = env.fresh();
			env.send(fresh);
			await settle();
			expect(env.sent).to.include(fresh.getId());
			env.monitor.handleSpendUnconfirmed(env.parent, 0);
			env.send();
			await settle();
			expect(
				env.sent.filter((id) => id === env.obsolete.getId())
			).to.have.length(2);
			expect(env.output().status).not.to.equal(
				OutputStatus.IRREVOCABLY_RESOLVED
			);
		} finally {
			env.watcher.stop();
		}
	});
});
