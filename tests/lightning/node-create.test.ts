/**
 * Issue #1707 (4C.1): LightningNode.create builds a node, restores it from
 * storage and starts it, in the order the constructor runs the same steps.
 * The constructor keeps running all three until the next major release.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { FeatureFlags } from '../../src/lightning/features/flags';

const SAVED_HEIGHT = 812_345;
const STEPS = ['wireChannelManagerEvents', 'restore', 'start'];
const TIMERS = [
	'cleanupTimer',
	'mppCleanupTimer',
	'missionControlTimer',
	'graphPruneTimer',
	'autoRebalanceTimer',
	'autoTuneFeesTimer'
];

function hash(label: string): Buffer {
	return crypto.createHash('sha256').update(`node-create-${label}`).digest();
}

function makeBasepoints(): IChannelBasepoints {
	return {
		fundingPubkey: getPublicKey(hash('funding')),
		revocationBasepoint: getPublicKey(hash('revocation')),
		paymentBasepoint: getPublicKey(hash('payment')),
		delayedPaymentBasepoint: getPublicKey(hash('delayed')),
		htlcBasepoint: getPublicKey(hash('htlc')),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(
	storage?: MemoryStorage,
	extra: Partial<INodeConfig> = {}
): INodeConfig {
	return {
		nodePrivateKey: hash('node'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(),
		perCommitmentSeed: hash('seed'),
		fundingPrivkey: hash('funding'),
		storage,
		...extra
	};
}

const PAYMENT_HASH = hash('payment-hash');

function seededStorage(): MemoryStorage {
	const storage = new MemoryStorage();
	storage.saveMetadata('blockHeight', String(SAVED_HEIGHT));
	storage.savePayment(PAYMENT_HASH.toString('hex'), {
		paymentHash: PAYMENT_HASH,
		preimage: hash('preimage'),
		amountMsat: 1_000n,
		direction: PaymentDirection.INCOMING,
		status: PaymentStatus.COMPLETED,
		createdAt: 1,
		completedAt: 2
	});
	return storage;
}

function armedTimers(node: LightningNode): string[] {
	const fields = node as unknown as Record<string, unknown>;
	return TIMERS.filter((name) => fields[name] != null);
}

type Method = (this: unknown, ...args: unknown[]) => unknown;

/**
 * Logs every call of the lifecycle steps on any node built while installed.
 * `fail` names a step that throws instead of running.
 */
function recordSteps(fail?: string): {
	steps: string[];
	uninstall: () => void;
} {
	const proto = LightningNode.prototype as unknown as Record<string, Method>;
	const steps: string[] = [];
	const originals = new Map<string, Method>();
	for (const name of STEPS) {
		const original = proto[name];
		originals.set(name, original);
		proto[name] = function (this: unknown, ...args: unknown[]): unknown {
			steps.push(name);
			if (name === fail) throw new Error(`${name} refused`);
			return original.apply(this, args);
		};
	}
	return {
		steps,
		uninstall: (): void => {
			for (const [name, original] of originals) proto[name] = original;
		}
	};
}

describe('LightningNode.create (issue #1707)', () => {
	const nodes: LightningNode[] = [];

	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	it('resolves to a node restored from storage and started', async () => {
		const node = await LightningNode.create(makeConfig(seededStorage()));
		nodes.push(node);

		expect(node.getCurrentBlockHeight()).to.equal(SAVED_HEIGHT);
		expect(node.getPayment(PAYMENT_HASH)?.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(armedTimers(node)).to.deep.equal([
			'cleanupTimer',
			'mppCleanupTimer',
			'missionControlTimer',
			'graphPruneTimer'
		]);
	});

	it('runs each step once, in the constructor order, with nothing between them', async () => {
		const recorder = recordSteps();
		try {
			nodes.push(new LightningNode(makeConfig(seededStorage())));
			const viaConstructor = recorder.steps.splice(0);

			const pending = LightningNode.create(makeConfig(seededStorage()));
			const beforeFirstYield = [...recorder.steps];
			nodes.push(await pending);

			expect(viaConstructor).to.deep.equal(STEPS);
			expect(beforeFirstYield).to.deep.equal(STEPS);
			expect(recorder.steps).to.deep.equal(STEPS);
		} finally {
			recorder.uninstall();
		}
	});

	it('arms the advisor timers from config, as the constructor does', async () => {
		const advisors: Partial<INodeConfig> = {
			autoRebalance: { enabled: true },
			autoTuneFees: { enabled: true }
		};
		const built = new LightningNode(makeConfig(seededStorage(), advisors));
		const created = await LightningNode.create(
			makeConfig(seededStorage(), advisors)
		);
		nodes.push(built, created);

		expect(armedTimers(created)).to.deep.equal(TIMERS);
		expect(armedTimers(built)).to.deep.equal(TIMERS);
	});

	it('rejects when the constructor refuses the config, and leaves later constructions whole', async () => {
		const pending = LightningNode.create(
			makeConfig(undefined, {
				localFeatures: FeatureFlags.empty(),
				ffor: { concurrent: { enabled: true } }
			})
		);
		expect(pending).to.be.instanceOf(Promise);
		let refusal: Error | undefined;
		try {
			await pending;
		} catch (err) {
			refusal = err as Error;
		}
		expect(refusal?.message).to.match(/fforConcurrent needs option_ff_receive/);

		const node = new LightningNode(makeConfig(seededStorage()));
		nodes.push(node);
		expect(node.getCurrentBlockHeight()).to.equal(SAVED_HEIGHT);
		expect(armedTimers(node)).to.include('graphPruneTimer');
	});

	it('rejects without starting when restore refuses', async () => {
		const recorder = recordSteps('restore');
		let refusal: Error | undefined;
		try {
			await LightningNode.create(makeConfig(seededStorage()));
		} catch (err) {
			refusal = err as Error;
		} finally {
			recorder.uninstall();
		}

		expect(refusal?.message).to.equal('restore refused');
		expect(recorder.steps).to.deep.equal([
			'wireChannelManagerEvents',
			'restore'
		]);
	});
});
