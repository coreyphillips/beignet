import { expect } from 'chai';
import crypto from 'crypto';
import sinon from 'sinon';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { type Channel } from '../../src/lightning/channel/channel';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../src/lightning/channel/auxiliary-funding';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type { IChannelPersistResult } from '../../src/lightning/channel/channel-actions';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { serializeChannelState } from '../../src/lightning/storage/serialization';

const hash = (value: string): Buffer =>
	crypto.createHash('sha256').update(value).digest();
const tick = async (): Promise<void> => {
	for (let i = 0; i < 12; i++) await Promise.resolve();
};
const deferred = (): {
	promise: Promise<void>;
	resolve(): void;
	reject(error: Error): void;
} => {
	let resolve!: () => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<void>((ok, fail) => {
		resolve = ok;
		reject = fail;
	});
	return { promise, resolve, reject };
};
const managers: ChannelManager[] = [];
const fixtureProvider = (sign: () => void): IChannelAuxiliaryProvider => ({
	buildCommitment: (context) => ({
		customData: Buffer.from('funding-gate-test'),
		outputLeaves: new Map(
			context.outputs
				.filter((output) => !output.role.startsWith('anchor_'))
				.map((output) => [
					output.outputIndex,
					{
						script: Buffer.concat([
							Buffer.from([0x6a, 0x20]),
							hash('gated asset leaf')
						])
					}
				])
		),
		secondLevelLeaves: new Map()
	}),
	signHtlcs: (): Map<bigint, Buffer> => {
		sign();
		return new Map();
	},
	verifyHtlcs: (_context, records) => records.size === 0,
	validateHtlc: (): never => {
		throw new Error('unexpected HTLC');
	},
	getHtlcAmount: (): never => {
		throw new Error('unexpected HTLC');
	},
	prepareShutdown: (): never => {
		throw new Error('unexpected shutdown');
	},
	verifyShutdown: () => false,
	buildClose: (): never => {
		throw new Error('unexpected close');
	}
});
interface Pair {
	alice: ChannelManager;
	bob: ChannelManager;
	aPub: string;
	bPub: string;
	descriptor: IAuxiliaryFundingDescriptor;
	channel: Channel;
	wire: { side: string; type: number; payload: Buffer }[];
	errors: string[];
	order: string[];
	durable: string[];
	signatures(): number;
	refuseWrites(): void;
	fund(): Buffer;
}
const pair = (
	hooks: Pick<IAuxiliaryChannelConfig, 'beforeAccept' | 'beforeFundingCreated'>
): Pair => {
	const descriptor: IAuxiliaryFundingDescriptor = {
		temporaryChannelId: hash('gate-temporary'),
		fundingTaprootMerkleRoot: hash('gate-root'),
		channelData: Buffer.from('proposed assets'),
		localBalance: 900n,
		remoteBalance: 100n
	};
	const wire: Pair['wire'] = [];
	const errors: string[] = [];
	const order: string[] = [];
	const durable: string[] = [];
	let signs = 0;
	let allowWrites = true;
	const configuration = (
		seed: number,
		incoming: IAuxiliaryFundingDescriptor
	): IChannelManagerConfig => {
		const keys = Array.from({ length: 5 }, (_, index) =>
			hash(`funding-gate:${seed}:${index}`)
		);
		return {
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: {
				fundingPubkey: getPublicKey(keys[0]),
				revocationBasepoint: getPublicKey(keys[1]),
				paymentBasepoint: getPublicKey(keys[2]),
				delayedPaymentBasepoint: getPublicKey(keys[3]),
				htlcBasepoint: getPublicKey(keys[4]),
				firstPerCommitmentPoint: Buffer.alloc(33)
			},
			localPerCommitmentSeed: hash(`funding-gate-seed:${seed}`),
			localFundingPrivkey: keys[0],
			htlcBasepointSecret: keys[4],
			preferTaproot: true,
			persistence: {
				persist: (request): IChannelPersistResult => {
					if (seed === 2 && !allowWrites)
						return { committed: false, outboxIds: [] };
					order.push(`${seed}:persist`);
					durable.push(
						JSON.stringify(
							serializeChannelState(request.channel.getFullState())
						)
					);
					return {
						committed: true,
						outboxIds:
							request.outbox?.outbound.map((_message, index) => index + 1) ?? []
					};
				}
			},
			auxiliaryChannels: {
				allowLegacyHtlcSignatures: () => true,
				provider: fixtureProvider(() => {
					if (seed === 2) signs++;
				}),
				resolveIncoming: (_peer, id) =>
					id.equals(descriptor.temporaryChannelId) ? incoming : undefined,
				...(seed === 2 ? hooks : {})
			}
		};
	};
	const alice = new ChannelManager(configuration(1, descriptor));
	const bob = new ChannelManager(
		configuration(2, { ...descriptor, localBalance: 100n, remoteBalance: 900n })
	);
	managers.push(alice, bob);
	const aPub = alice['config'].localBasepoints.fundingPubkey.toString('hex');
	const bPub = bob['config'].localBasepoints.fundingPubkey.toString('hex');
	alice.on('error', (_id, error: string) => errors.push(`alice:${error}`));
	bob.on('error', (_id, error: string) => errors.push(`bob:${error}`));
	alice.on('message:outbound', (_peer, type, payload) => {
		wire.push({ side: 'alice', type, payload: Buffer.from(payload) });
		order.push(`1:wire:${type}`);
		bob.handleMessage(aPub, type, payload);
	});
	bob.on('message:outbound', (_peer, type, payload) => {
		wire.push({ side: 'bob', type, payload: Buffer.from(payload) });
		order.push(`2:wire:${type}`);
		alice.handleMessage(bPub, type, payload);
	});
	const channel = alice.openChannel(bPub, 2_000_000n, 500_000_000n, undefined, {
		auxiliary: descriptor
	});
	return {
		alice,
		bob,
		aPub,
		bPub,
		descriptor,
		channel,
		wire,
		errors,
		order,
		durable,
		signatures: () => signs,
		refuseWrites: (): void => {
			allowWrites = false;
		},
		fund: (): Buffer => {
			const id = alice.createFunding(
				channel,
				hash('gate-funding'),
				0,
				Buffer.alloc(64)
			);
			expect(id, errors.join('; ')).not.to.equal(null);
			return id!;
		}
	};
};
const count = (p: Pair, type: MessageType): number =>
	p.wire.filter((message) => message.side === 'bob' && message.type === type)
		.length;
const created = (p: Pair): Buffer =>
	p.wire.find((message) => message.type === MessageType.FUNDING_CREATED)!
		.payload;

describe('native auxiliary funding validation gates', () => {
	afterEach(() => {
		for (const manager of managers.splice(0)) manager.detachFromPeerManager();
		sinon.restore();
	});
	it('awaits durable acceptance and funding proof checks before sending or signing, coalescing duplicates', async () => {
		const accept = deferred();
		const funding = deferred();
		let accepts = 0;
		let proofs = 0;
		const p = pair({
			beforeAccept: async () => {
				accepts++;
				await accept.promise;
				p.order.push('verified:accept');
			},
			beforeFundingCreated: async () => {
				proofs++;
				await funding.promise;
				p.bob.setAuxiliaryFundingData(
					p.aPub,
					p.descriptor.temporaryChannelId,
					Buffer.from('verified suffixes')
				);
				p.order.push('verified:funding');
			}
		});
		await tick();
		expect(accepts).to.equal(1);
		expect(count(p, MessageType.ACCEPT_CHANNEL)).to.equal(0);
		accept.resolve();
		await tick();
		expect(count(p, MessageType.ACCEPT_CHANNEL)).to.equal(1);
		expect(p.order.indexOf('verified:accept')).to.be.lessThan(
			p.order.indexOf(`2:wire:${MessageType.ACCEPT_CHANNEL}`)
		);
		const id = p.fund();
		for (let i = 0; i < 256; i++)
			p.bob.handleMessage(
				p.aPub,
				MessageType.FUNDING_CREATED,
				Buffer.from(created(p))
			);
		await tick();
		expect(proofs).to.equal(1);
		expect(p.signatures()).to.equal(0);
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(0);
		funding.resolve();
		await tick();
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(1);
		expect(p.order.indexOf('verified:funding')).to.be.lessThan(
			p.order.indexOf(`2:wire:${MessageType.FUNDING_SIGNED}`)
		);
		expect(
			p.durable.some((record) =>
				record.includes(Buffer.from('verified suffixes').toString('hex'))
			)
		).to.equal(true);
		expect(
			p.bob
				.getChannel(id)!
				.getFullState()
				.auxiliaryState!.channelData.toString()
		).to.equal('verified suffixes');
		expect(p.errors).to.deep.equal([]);
	});
	it('aborts a changed duplicate before signing and ignores a later successful validation', async () => {
		const funding = deferred();
		const p = pair({ beforeFundingCreated: () => funding.promise });
		p.fund();
		await tick();
		const conflict = Buffer.from(created(p));
		conflict[32] ^= 1;
		p.bob.handleMessage(p.aPub, MessageType.FUNDING_CREATED, conflict);
		expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
			undefined
		);
		funding.resolve();
		await tick();
		expect(p.signatures()).to.equal(0);
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(0);
	});
	it('times out proof validation and does not sign when the old validation later resolves', async () => {
		const clock = sinon.useFakeTimers();
		const funding = deferred();
		const p = pair({ beforeFundingCreated: () => funding.promise });
		p.fund();
		await tick();
		await clock.tickAsync(120_001);
		expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
			undefined
		);
		funding.resolve();
		await tick();
		expect(p.signatures()).to.equal(0);
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(0);
	});
	it('detaches pending validation without a late signature or retained timer', async () => {
		const clock = sinon.useFakeTimers();
		const funding = deferred();
		const p = pair({ beforeFundingCreated: () => funding.promise });
		p.fund();
		await tick();
		p.bob.detachFromPeerManager();
		expect(clock.countTimers()).to.equal(0);
		funding.resolve();
		await tick();
		expect(p.signatures()).to.equal(0);
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(0);
	});
	it('refuses failed acceptance without emitting its negotiated keys', async () => {
		const accept = deferred();
		const p = pair({ beforeAccept: () => accept.promise });
		await tick();
		accept.reject(new Error('negotiation store unavailable'));
		await tick();
		expect(count(p, MessageType.ACCEPT_CHANNEL)).to.equal(0);
		expect(p.bob.getTempChannel(p.descriptor.temporaryChannelId)).to.equal(
			undefined
		);
	});
	it('withholds the initial funding signature if its native persistence fails', async () => {
		const funding = deferred();
		const p = pair({ beforeFundingCreated: () => funding.promise });
		p.fund();
		await tick();
		p.refuseWrites();
		funding.resolve();
		await tick();
		expect(count(p, MessageType.FUNDING_SIGNED)).to.equal(0);
	});
});
