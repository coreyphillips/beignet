import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	hasAuxiliaryFeeSourceConflict,
	type IAuxiliaryFeeSourceCheck
} from '../../src/lightning/chain/auxiliary-fee-source';
import type { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import type { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ChainActionType,
	type IFeeBumpAndBroadcastChainAction
} from '../../src/lightning/chain/types';
import type { IFundingProvider } from '../../src/lightning/node/types';
import { COMMIT_ALL } from './helpers/channel-persistence';

function fixture() {
	const pubkey = Buffer.from(ecc.pointFromScalar(Buffer.alloc(32, 7), true)!);
	const script = Buffer.concat([Buffer.from([0x51, 0x20]), pubkey.subarray(1)]);
	const parent = new bitcoin.Transaction();
	parent.addInput(Buffer.alloc(32, 12), 1);
	parent.addOutput(script, 355);
	parent.addOutput(script, 355);
	const claim = new bitcoin.Transaction();
	claim.version = 2;
	claim.addInput(parent.getHash(), 0, 0xfffffffd);
	claim.addOutput(script, 355);
	const tower = claim.clone();
	tower.locktime = 20;
	tower.addInput(Buffer.alloc(32, 13), 0);
	const unrelated = new bitcoin.Transaction();
	unrelated.addInput(parent.getHash(), 1);
	unrelated.addOutput(script, 355);
	const transactions = new Map([
		[parent.getId(), parent.toBuffer()],
		[tower.getId(), tower.toBuffer()],
		[unrelated.getId(), unrelated.toBuffer()]
	]);
	let history = [
		{ txid: parent.getId(), height: 1 },
		{ txid: tower.getId(), height: 2 }
	];
	const backend = {
		getTransaction: async (id: string): Promise<Buffer> => {
			const raw = transactions.get(id);
			if (!raw) throw new Error('not indexed');
			return raw;
		},
		getScriptHashHistory: async (): Promise<typeof history> => history
	} as unknown as IChainBackend;
	const check: IAuxiliaryFeeSourceCheck = {
		transaction: claim.toBuffer(),
		prevoutScripts: [script],
		prevoutValues: [355n]
	};
	return {
		pubkey,
		parent,
		claim,
		tower,
		unrelated,
		transactions,
		backend,
		check,
		setHistory: (next: typeof history): void => {
			history = next;
		}
	};
}

function managerFixture(value: ReturnType<typeof fixture>) {
	const id = Buffer.alloc(32, 14),
		errors: string[] = [];
	let selections = 0,
		signatures = 0,
		current = true;
	const manager = new ChannelManager({
		localBasepoints: {
			fundingPubkey: value.pubkey,
			revocationBasepoint: value.pubkey,
			paymentBasepoint: value.pubkey,
			delayedPaymentBasepoint: value.pubkey,
			htlcBasepoint: value.pubkey,
			firstPerCommitmentPoint: value.pubkey
		},
		localPerCommitmentSeed: Buffer.alloc(32, 9),
		localFundingPrivkey: Buffer.alloc(32, 7),
		persistence: COMMIT_ALL,
		hasAuxiliarySweepConflict: (check) =>
			hasAuxiliaryFeeSourceConflict(value.backend, check)
	});
	manager.on('error', (_id: Buffer | null, message: string) =>
		errors.push(message)
	);
	manager.setFundingProvider({
		selectFeeBumpInputs: async () => {
			selections++;
			throw new Error('genuine wallet fee shortage');
		}
	} as unknown as IFundingProvider);
	const internal = manager as unknown as {
		monitors: Map<string, ChainMonitor>;
		_handleFeeBumpAndBroadcast(
			id: Buffer,
			action: IFeeBumpAndBroadcastChainAction
		): Promise<void>;
	};
	const monitor = { getTrackedOutputs: () => [] } as unknown as ChainMonitor;
	internal.monitors.set(id.toString('hex'), monitor);
	const action: IFeeBumpAndBroadcastChainAction = {
		type: ChainActionType.FEE_BUMP_AND_BROADCAST,
		kind: 'auxiliary-sweep-fee-attach',
		tx: value.claim.toBuffer(),
		description: 'restored revoked child',
		feeratePerVbyte: 1,
		isCurrent: () => current,
		auxiliarySweep: {
			prevoutScripts: [...value.check.prevoutScripts],
			prevoutValues: [...value.check.prevoutValues],
			sign: () => {
				signatures++;
				throw new Error('unexpected signature');
			},
			finalize: () => {
				throw new Error('unexpected finalization');
			}
		}
	};
	return {
		id,
		internal,
		errors,
		action,
		run: () => internal._handleFeeBumpAndBroadcast(id, action),
		selections: () => selections,
		signatures: () => signatures,
		invalidate: () => {
			current = false;
		}
	};
}

describe('Auxiliary fee source preflight', () => {
	it('does not select or sign fees for a restored child already spent by a tower', async () => {
		const value = fixture(),
			manager = managerFixture(value);
		await manager.run();
		expect(manager.selections()).equal(0);
		expect(manager.signatures()).equal(0);
		expect(manager.errors).deep.equal([]);
		// A reorg removing the spend leaves the claim eligible and real fee errors visible.
		value.setHistory([{ txid: value.parent.getId(), height: 1 }]);
		await manager.run();
		expect(manager.selections()).equal(1);
		expect(manager.errors).length(1);
		expect(manager.errors[0]).include('genuine wallet fee shortage');
	});

	it('preserves fee competition against all unconfirmed spends and defers confirmed spends', async () => {
		const value = fixture(),
			manager = managerFixture(value);
		for (const height of [-1, 0]) {
			value.setHistory([{ txid: value.tower.getId(), height }]);
			expect(
				await hasAuxiliaryFeeSourceConflict(value.backend, value.check)
			).equal(false);
			await manager.run();
		}
		expect(manager.selections()).equal(2);
		expect(
			manager.errors.every((error) =>
				error.includes('genuine wallet fee shortage')
			)
		).equal(true);
		value.setHistory([{ txid: value.tower.getId(), height: 2 }]);
		expect(
			await hasAuxiliaryFeeSourceConflict(value.backend, value.check)
		).equal(true);
		await manager.run();
		expect(manager.selections()).equal(2);
	});

	it('requires a matching transaction identity and exact source outpoint', async () => {
		const value = fixture();
		value.setHistory([{ txid: value.unrelated.getId(), height: 2 }]);
		expect(
			await hasAuxiliaryFeeSourceConflict(value.backend, value.check)
		).equal(false);
		value.setHistory([{ txid: value.tower.getId(), height: 2 }]);
		value.transactions.set(value.tower.getId(), value.unrelated.toBuffer());
		expect(
			await hasAuxiliaryFeeSourceConflict(value.backend, value.check)
		).equal(false);
	});

	it('authenticates the source value before consulting spending history', async () => {
		const value = fixture(),
			manager = managerFixture(value);
		manager.action.auxiliarySweep!.prevoutValues[0] = 356n;
		await manager.run();
		expect(manager.selections()).equal(0);
		expect(manager.errors[0]).include('authenticated prevout');
	});

	it('checks every original input of an aggregate without changing its tracked state', async () => {
		const value = fixture();
		value.claim.addInput(value.parent.getHash(), 1, 0xfffffffd);
		value.check.transaction = value.claim.toBuffer();
		value.check.prevoutScripts = [
			value.parent.outs[0].script,
			value.parent.outs[1].script
		];
		value.check.prevoutValues = [355n, 355n];
		value.setHistory([{ txid: value.unrelated.getId(), height: 2 }]);
		const manager = managerFixture(value);
		await manager.run();
		expect(manager.selections()).equal(0);
		expect(manager.signatures()).equal(0);
		expect(manager.errors).deep.equal([]);
		value.setHistory([]);
		await manager.run();
		expect(manager.selections()).equal(1);
		expect(manager.errors[0]).include('genuine wallet fee shortage');
	});

	for (const replaceMonitor of [false, true])
		it(`rechecks ${
			replaceMonitor ? 'monitor identity' : 'generation'
		} after asynchronous source verification`, async () => {
			const value = fixture(),
				manager = managerFixture(value);
			let release!: () => void, started!: () => void;
			const waiting = new Promise<void>((resolve) => {
				release = resolve;
			});
			const began = new Promise<void>((resolve) => {
				started = resolve;
			});
			value.backend.getScriptHashHistory = async () => {
				started();
				await waiting;
				return [];
			};
			const running = manager.run();
			await began;
			if (replaceMonitor)
				manager.internal.monitors.set(
					manager.id.toString('hex'),
					{} as ChainMonitor
				);
			else manager.invalidate();
			release();
			await running;
			expect(manager.selections()).equal(0);
			expect(manager.signatures()).equal(0);
			expect(manager.errors).deep.equal([]);
		});

	it('keeps unavailable history inconclusive and preserves genuine fee failures', async () => {
		const value = fixture(),
			manager = managerFixture(value);
		value.backend.getScriptHashHistory = async () => {
			throw new Error('offline');
		};
		await manager.run();
		expect(manager.selections()).equal(1);
		expect(manager.errors[0]).include('genuine wallet fee shortage');
	});
});
