/**
 * Issue #1394: a connected peer may hold at most four inbound opens unfunded
 * at once. Before the cap, every open_channel / open_channel2 with a fresh
 * temporary id derived a key set and retained a Channel until the peer
 * disconnected, so a peer that stayed connected could accumulate them
 * without bound. The fifth is refused on the wire before any key is derived.
 *
 * Issue #1456: an open promoted by funding_created keeps its slot until its
 * funding confirms, across disconnect and restore, because the txid it names
 * need not exist.
 *
 * Issue #1457: within that quota, the prev_tx bytes the opens' tx_add_input
 * messages leave retained are capped per session and across sessions.
 *
 * Issue #1500: a chain check still waiting on the backend holds none of
 * those bytes once the input or its session is gone, and a refused input
 * launches no check.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import v8 from 'v8';
import vm from 'vm';
import * as bitcoin from 'bitcoinjs-lib';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import { MAX_PEER_PREVTX_BYTES_PER_SESSION } from '../../src/lightning/interactive-tx/validation';
import {
	encodeTxAddInputMessage,
	encodeTxRemoveInputMessage
} from '../../src/lightning/message/interactive-tx';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { deriveV2TemporaryChannelId } from '../../src/lightning/channel/validation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	encodeOpenChannel2Message,
	IOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';

// lib is pinned to es2020, which predates WeakRef; Node has it.
declare class WeakRef<T extends object> {
	constructor(target: T);
	deref(): T | undefined;
}

const PEER_A = '02' + 'a1'.repeat(32);
const PEER_B = '02' + 'b2'.repeat(32);
const VICTIM = '03' + 'cd'.repeat(32);
const noop = (): void => {};

function makeSeed(tag: string): Buffer {
	return crypto.createHash('sha256').update(`ioc-${tag}`).digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(derivePrivkey(seed, i));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

/** A deriver that advances the index, so a derivation shows on the counter. */
function makePerChannelKeys(channelIndex: number): IPerChannelKeys {
	const seed = makeSeed(`per-channel-${channelIndex}`);
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		fundingPrivkey,
		basepoints: {
			...makeBasepoints(seed),
			fundingPubkey: getPublicKey(fundingPrivkey)
		},
		perCommitmentSeed: makeSeed(`pcs-${channelIndex}`),
		htlcBasepointSecret: derivePrivkey(seed, 4)
	};
}

/** keyOffset keeps two managers that complete an open off each other's keys. */
function makeManager(
	tag: string,
	keyOffset = 0,
	extra: Partial<IChannelManagerConfig> = {}
): ChannelManager {
	const seed = makeSeed(tag);
	const manager = new ChannelManager({
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: (index: number): IPerChannelKeys =>
			makePerChannelKeys(index + keyOffset),
		...extra
	});
	manager.on('error', noop);
	return manager;
}

/** Wire the opener to the victim, which knows it as PEER_A. */
function connect(victim: ChannelManager, opener: ChannelManager): void {
	opener.on('message:outbound', (peer: string, type: number, body: Buffer) => {
		if (peer === VICTIM) victim.handleMessage(PEER_A, type, body);
	});
	victim.on('message:outbound', (peer: string, type: number, body: Buffer) => {
		if (peer === PEER_A) opener.handleMessage(VICTIM, type, body);
	});
}

/**
 * A complete v1 open whose correctly signed funding_created names a
 * transaction that does not exist. The victim promotes it all the same.
 */
function fundWithNonexistentTx(
	victim: ChannelManager,
	opener: ChannelManager
): Buffer {
	const channel = opener.openChannel(VICTIM, 100_000n);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		Buffer.alloc(64)
	);
	expect(channelId, 'funding_created was accepted').to.not.equal(null);
	expect(victim.getTempChannel(channel.getTemporaryChannelId())).to.equal(
		undefined
	);
	expect(victim.getChannel(channelId!)?.getState()).to.equal(
		ChannelState.AWAITING_FUNDING_CONFIRMED
	);
	return channelId!;
}

/** An open_channel payload with a fresh temporary id, captured off the wire. */
function offerOpen(opener: ChannelManager): { payload: Buffer; id: Buffer } {
	let captured: Buffer | null = null;
	const capture = (_peer: string, type: number, payload: Buffer): void => {
		if (type === MessageType.OPEN_CHANNEL) captured = payload;
	};
	opener.on('message:outbound', capture);
	const channel = opener.openChannel(VICTIM, 100_000n);
	opener.off('message:outbound', capture);
	expect(captured, 'captured the open_channel').to.not.equal(null);
	return { payload: captured!, id: channel.getTemporaryChannelId() };
}

function offerOpen2(tag: string): { payload: Buffer; id: Buffer } {
	const remoteBp = makeBasepoints(makeSeed(`${tag}-remote`));
	const remoteSeed = makeSeed(`${tag}-remote-pcs`);
	remoteBp.firstPerCommitmentPoint = perCommitmentPointFromSecret(
		generateFromSeed(remoteSeed, MAX_INDEX)
	);
	const msg: IOpenChannel2Message = {
		chainHash: REGTEST_CHAIN_HASH,
		channelId: deriveV2TemporaryChannelId(remoteBp.revocationBasepoint),
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 500,
		fundingSatoshis: 100_000n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 100_000_000n,
		htlcMinimumMsat: 1n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 30,
		locktime: 0,
		fundingPubkey: remoteBp.fundingPubkey,
		revocationBasepoint: remoteBp.revocationBasepoint,
		paymentBasepoint: remoteBp.paymentBasepoint,
		delayedPaymentBasepoint: remoteBp.delayedPaymentBasepoint,
		htlcBasepoint: remoteBp.htlcBasepoint,
		firstPerCommitmentPoint: remoteBp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(remoteSeed, MAX_INDEX - 1n)
		),
		channelFlags: 0x01,
		channelType: Buffer.from('1000', 'hex')
	};
	return { payload: encodeOpenChannel2Message(msg), id: msg.channelId };
}

interface IAnswer {
	wireTypes: number[];
	wireErrors: Array<{ channelId: Buffer; data: string }>;
}

/** Feed one inbound message and collect what went back on the wire. */
function inbound(
	target: ChannelManager,
	from: string,
	type: number,
	payload: Buffer
): IAnswer {
	const wire: Array<{ type: number; payload: Buffer }> = [];
	const onWire = (_peer: string, t: number, body: Buffer): void => {
		wire.push({ type: t, payload: body });
	};
	target.on('message:outbound', onWire);
	target.handleMessage(from, type, payload);
	target.off('message:outbound', onWire);
	return {
		wireTypes: wire.map((w) => w.type),
		wireErrors: wire
			.filter((w) => w.type === MessageType.ERROR)
			.map((w) => {
				const decoded = decodeErrorMessage(w.payload);
				return {
					channelId: decoded.channelId,
					data: decoded.data.toString('utf8')
				};
			})
	};
}

function acceptV1(
	target: ChannelManager,
	from: string,
	opener: ChannelManager
): void {
	const open = offerOpen(opener);
	const answer = inbound(target, from, MessageType.OPEN_CHANNEL, open.payload);
	expect(answer.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
	expect(target.getTempChannel(open.id)).to.not.equal(undefined);
}

function acceptV2(target: ChannelManager, from: string, tag: string): Buffer {
	const open = offerOpen2(tag);
	const answer = inbound(target, from, MessageType.OPEN_CHANNEL2, open.payload);
	expect(answer.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL2]);
	expect(target.getTempChannel(open.id)).to.not.equal(undefined);
	return open.id;
}

/** The refusal, scoped to the open's id, with nothing derived or retained. */
function expectRefused(
	target: ChannelManager,
	open: { id: Buffer },
	answer: IAnswer,
	indexBefore: number
): void {
	expect(answer.wireTypes).to.deep.equal([MessageType.ERROR]);
	expect(answer.wireErrors[0].channelId.equals(open.id)).to.equal(true);
	expect(answer.wireErrors[0].data).to.match(
		/4 opens from this peer are already pending/
	);
	expect(target.getTempChannel(open.id)).to.equal(undefined);
	expect(target.nextChannelIndex).to.equal(indexBefore);
}

describe('Pending inbound open cap (issue #1394)', () => {
	it('refuses a fifth unfunded open from one peer before deriving keys, v1 and v2 sharing the quota', () => {
		const victim = makeManager('victim');
		const opener = makeManager('opener');
		acceptV1(victim, PEER_A, opener);
		acceptV1(victim, PEER_A, opener);
		acceptV2(victim, PEER_A, 'a-1');
		acceptV2(victim, PEER_A, 'a-2');
		const index = victim.nextChannelIndex;

		const v1 = offerOpen(opener);
		expectRefused(
			victim,
			v1,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, v1.payload),
			index
		);
		const v2 = offerOpen2('a-3');
		expectRefused(
			victim,
			v2,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL2, v2.payload),
			index
		);
		expect(victim.listChannels()).to.have.length(4);
	});

	it('counts only opens the peer proposed, per peer, and a disconnect frees the quota', () => {
		const victim = makeManager('victim-scope');
		const opener = makeManager('opener-scope');
		// Our own pending opens to the peer are not its opens.
		for (let i = 0; i < 4; i++) victim.openChannel(PEER_A, 100_000n);
		for (let i = 0; i < 4; i++) acceptV1(victim, PEER_A, opener);
		const refused = offerOpen(opener);
		expectRefused(
			victim,
			refused,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, refused.payload),
			victim.nextChannelIndex
		);

		// Another peer has a quota of its own.
		acceptV1(victim, PEER_B, opener);
		acceptV2(victim, PEER_B, 'b-1');

		// The disconnect sweep retires the peer's pending opens, and with
		// them the quota they held.
		victim.handlePeerDisconnected(PEER_A);
		acceptV1(victim, PEER_A, opener);
		acceptV2(victim, PEER_A, 'a-after');
	});
});

describe('Unconfirmed inbound channels keep their quota (issue #1456)', () => {
	function probeRefused(victim: ChannelManager, probe: ChannelManager): void {
		const open = offerOpen(probe);
		const index = victim.nextChannelIndex;
		expectRefused(
			victim,
			open,
			inbound(victim, PEER_A, MessageType.OPEN_CHANNEL, open.payload),
			index
		);
	}

	it('counts opens promoted with a nonexistent funding tx, across disconnect, until the funding confirms', () => {
		const victim = makeManager('victim-promoted');
		const opener = makeManager('opener-promoted', 1000);
		const probe = makeManager('probe-promoted', 2000);
		connect(victim, opener);
		const funded: Buffer[] = [];
		for (let i = 0; i < 4; i++) {
			funded.push(fundWithNonexistentTx(victim, opener));
		}
		probeRefused(victim, probe);

		victim.handlePeerDisconnected(PEER_A);
		expect(victim.getChannelsByPeer(PEER_A)).to.have.length(4);
		probeRefused(victim, probe);

		// Funding our own watcher saw gives that channel's slot back.
		victim.handleFundingConfirmed(funded[0]);
		expect(victim.getChannel(funded[0])!.isFundingKnownOnChain()).to.equal(
			true
		);
		acceptV1(victim, PEER_A, probe);
		probeRefused(victim, probe);
	});

	it('counts unconfirmed inbound channels restored from disk', () => {
		const victim = makeManager('victim-restore');
		const opener = makeManager('opener-restore', 1000);
		connect(victim, opener);
		for (let i = 0; i < 4; i++) fundWithNonexistentTx(victim, opener);

		const restarted = makeManager('victim-restore');
		for (const channel of victim.getChannelsByPeer(PEER_A)) {
			const row = deserializeChannelState(
				serializeChannelState(channel.getFullState())
			);
			restarted.restoreChannel(
				new Channel(row),
				PEER_A,
				channel.channelKeyIndex
			);
		}
		probeRefused(restarted, makeManager('probe-restore', 2000));
	});

	it('frees the slot of a channel whose close resolved, with no funding confirmation recorded', () => {
		const victim = makeManager('victim-resolved');
		const opener = makeManager('opener-resolved', 1000);
		const probe = makeManager('probe-resolved', 2000);
		connect(victim, opener);
		const funded: Buffer[] = [];
		for (let i = 0; i < 4; i++) {
			funded.push(fundWithNonexistentTx(victim, opener));
		}
		probeRefused(victim, probe);

		const closed = victim.forceClose(
			funded[0],
			Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 1)])
		);
		expect(closed.ok, closed.error).to.equal(true);
		expect(victim.markChannelResolved(funded[0])).to.equal(true);
		expect(victim.getChannel(funded[0])!.isFundingKnownOnChain()).to.equal(
			false
		);
		acceptV1(victim, PEER_A, probe);
	});

	it('leaves trusted zero-conf opens out of the count', () => {
		const victim = makeManager('victim-zero-conf');
		const opener = makeManager('opener-zero-conf', 1000);
		connect(victim, opener);
		victim.addTrustedPeer(PEER_A);
		opener.addTrustedPeer(VICTIM);
		for (let i = 0; i < 5; i++) {
			const channel = opener.openChannel(
				VICTIM,
				100_000n,
				undefined,
				undefined,
				{ trusted: true }
			);
			const channelId = opener.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, `open ${i + 1} was accepted`).to.not.equal(null);
			expect(victim.getChannel(channelId!)).to.not.equal(undefined);
		}
	});
});

describe('Retained peer prev_tx bytes (issue #1457)', () => {
	/** The reproduction's prev_tx: 65,393 bytes, a P2WPKH at vout 0. */
	function makeLargePrevTx(paddingBytes = 65_300): Buffer {
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.addInput(crypto.randomBytes(32), 0);
		tx.addOutput(
			Buffer.concat([Buffer.from('0014', 'hex'), crypto.randomBytes(20)]),
			10_000
		);
		tx.addOutput(Buffer.alloc(paddingBytes, 0x6a), 0);
		return tx.toBuffer();
	}
	const prevTx = makeLargePrevTx();

	/** Send one tx_add_input and return the errors it raised. */
	function addInput(
		victim: ChannelManager,
		from: string,
		channelId: Buffer,
		serialId: bigint,
		tx = prevTx
	): string[] {
		const errors: string[] = [];
		const onError = (_id: Buffer | null, message: string): void => {
			errors.push(message);
		};
		victim.on('error', onError);
		victim.handleMessage(
			from,
			MessageType.TX_ADD_INPUT,
			encodeTxAddInputMessage({
				channelId,
				serialId,
				prevTx: tx,
				prevTxVout: 0,
				sequence: 0xfffffffd
			})
		);
		victim.off('error', onError);
		return errors;
	}

	function retained(victim: ChannelManager): number {
		return victim
			.listChannels()
			.reduce((sum, c) => sum + c.getRetainedPeerPrevTxBytes(), 0);
	}

	it("caps each of a peer's four sessions, so 1,008 inputs no longer retain 66 MB", () => {
		expect(prevTx.length).to.equal(65_393);
		const fit = Math.floor(MAX_PEER_PREVTX_BYTES_PER_SESSION / prevTx.length);
		const victim = makeManager('victim-prevtx');
		const ids = [1, 2, 3, 4].map((i) => acceptV2(victim, PEER_A, `p-${i}`));

		for (const id of ids) {
			for (let i = 0; i < fit; i++) {
				expect(addInput(victim, PEER_A, id, BigInt(2 * i))).to.deep.equal([]);
			}
		}
		expect(retained(victim)).to.equal(4 * fit * prevTx.length);
		expect(retained(victim)).to.be.at.most(
			4 * MAX_PEER_PREVTX_BYTES_PER_SESSION
		);

		for (const id of ids) {
			const errors = addInput(victim, PEER_A, id, BigInt(2 * fit));
			expect(errors).to.have.length(1);
			expect(errors[0]).to.contain('in this session');
			expect(victim.getTempChannel(id)).to.equal(undefined);
		}
		expect(retained(victim)).to.equal(0);
	});

	it('shares one budget across sessions and peers, freed by tx_remove_input and by disconnect', () => {
		const victim = makeManager('victim-budget', 0, {
			maxRetainedPeerPrevTxBytes: 3 * prevTx.length
		});
		const a1 = acceptV2(victim, PEER_A, 'budget-a-1');
		const a2 = acceptV2(victim, PEER_A, 'budget-a-2');
		const b1 = acceptV2(victim, PEER_B, 'budget-b-1');

		expect(addInput(victim, PEER_A, a1, 0n)).to.deep.equal([]);
		expect(addInput(victim, PEER_A, a1, 2n)).to.deep.equal([]);
		expect(addInput(victim, PEER_A, a2, 0n)).to.deep.equal([]);

		// A fourth prev_tx anywhere crosses the budget and fails only the
		// session it was sent on.
		const refused = addInput(victim, PEER_A, a2, 2n);
		expect(refused).to.have.length(1);
		expect(refused[0]).to.contain('node-wide budget');
		expect(victim.getTempChannel(a2)).to.equal(undefined);
		expect(victim.getTempChannel(a1)!.getRetainedPeerPrevTxBytes()).to.equal(
			2 * prevTx.length
		);

		// The failed session's bytes came back, and so does a removed input's.
		expect(addInput(victim, PEER_B, b1, 0n)).to.deep.equal([]);
		victim.handleMessage(
			PEER_A,
			MessageType.TX_REMOVE_INPUT,
			encodeTxRemoveInputMessage({ channelId: a1, serialId: 0n })
		);
		expect(retained(victim)).to.equal(2 * prevTx.length);
		expect(addInput(victim, PEER_B, b1, 2n)).to.deep.equal([]);

		// So do a disconnected peer's sessions.
		victim.handlePeerDisconnected(PEER_A);
		expect(victim.getTempChannel(a1)).to.equal(undefined);
		expect(addInput(victim, PEER_B, b1, 4n)).to.deep.equal([]);
		expect(retained(victim)).to.equal(3 * prevTx.length);
		expect(addInput(victim, PEER_B, b1, 6n)[0]).to.contain('node-wide budget');
	});

	describe('pending chain checks (issue #1500)', () => {
		type Verify = NonNullable<
			IChannelManagerConfig['verifyRemoteFundingInput']
		>;
		interface IPendingCheck {
			input: Parameters<Verify>[0];
			resolve: (verdict: 'unspent' | 'spent-or-missing' | 'unknown') => void;
		}

		/**
		 * Answers only when the test says so, and holds its argument meanwhile,
		 * as the node's own verifier does across its backend query.
		 */
		function deferredVerifier(checks: IPendingCheck[]): Verify {
			return (input) =>
				new Promise((resolve) => {
					checks.push({ input, resolve });
				});
		}

		/** The memory behind the prev_tx the session's builder kept. */
		function watchKeptPrevTx(
			victim: ChannelManager,
			channelId: Buffer,
			serialId: bigint,
			backingBytes = prevTx.length
		): WeakRef<ArrayBufferLike> {
			const kept = victim
				.getTempChannel(channelId)!
				.getDualFundingSession()!
				.getTxBuilder()!
				.getSession()
				.inputs.get(serialId.toString())!.prevTx!;
			expect(kept.buffer.byteLength).to.equal(backingBytes);
			return new WeakRef(kept.buffer);
		}

		/** A full collection, once this job's WeakRef targets are released. */
		async function collectGarbage(): Promise<void> {
			await new Promise((resolve) => setImmediate(resolve));
			v8.setFlagsFromString('--expose-gc');
			(vm.runInNewContext('gc') as () => void)();
		}

		it('eight dropped sessions retain no prev_tx while their checks are pending', async () => {
			const checks: IPendingCheck[] = [];
			const victim = makeManager('victim-pending', 0, {
				verifyRemoteFundingInput: deferredVerifier(checks)
			});
			const watched: Array<WeakRef<ArrayBufferLike>> = [];
			for (let i = 0; i < 8; i++) {
				const id = acceptV2(victim, PEER_A, `pending-${i}`);
				expect(
					addInput(victim, PEER_A, id, 0n, makeLargePrevTx())
				).to.deep.equal([]);
				watched.push(watchKeptPrevTx(victim, id, 0n));
				victim.handlePeerDisconnected(PEER_A);
			}
			expect(checks).to.have.length(8);
			expect(retained(victim)).to.equal(0);

			await collectGarbage();
			expect(
				watched.filter((ref) => ref.deref() !== undefined),
				'prev_txs still reachable'
			).to.have.length(0);

			const sent: number[] = [];
			victim.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
			for (const check of checks) check.resolve('spent-or-missing');
			await new Promise((resolve) => setImmediate(resolve));
			expect(sent, 'late verdicts found nothing to abort').to.deep.equal([]);
		});

		it('dropped sessions retain no pooled prev_tx while their checks are pending', async () => {
			const checks: IPendingCheck[] = [];
			const victim = makeManager('victim-pooled', 0, {
				verifyRemoteFundingInput: deferredVerifier(checks)
			});
			const watched: Array<WeakRef<ArrayBufferLike>> = [];
			for (let i = 0; i < 16; i++) {
				const id = acceptV2(victim, PEER_A, `pooled-${i}`);
				expect(
					addInput(victim, PEER_A, id, 0n, makeLargePrevTx(i % 2 ? 0 : 3000))
				).to.deep.equal([]);
				watched.push(watchKeptPrevTx(victim, id, 0n, Buffer.poolSize));
				victim.handlePeerDisconnected(PEER_A);
			}
			expect(checks).to.have.length(16);
			expect(victim.listChannels()).to.have.length(0);

			// The active buffer pool itself keeps its current slab alive.
			for (let i = 0; i < 16; i++) Buffer.allocUnsafe(Buffer.poolSize / 2 - 1);
			await collectGarbage();
			expect(
				watched.filter((ref) => ref.deref() !== undefined),
				'prev_tx slabs still reachable'
			).to.have.length(0);
		});

		it('a check pending past tx_remove_input retains no prev_tx', async () => {
			const checks: IPendingCheck[] = [];
			const victim = makeManager('victim-removed', 0, {
				verifyRemoteFundingInput: deferredVerifier(checks)
			});
			const id = acceptV2(victim, PEER_A, 'removed');
			expect(addInput(victim, PEER_A, id, 0n, makeLargePrevTx())).to.deep.equal(
				[]
			);
			const watched = watchKeptPrevTx(victim, id, 0n);
			victim.handleMessage(
				PEER_A,
				MessageType.TX_REMOVE_INPUT,
				encodeTxRemoveInputMessage({ channelId: id, serialId: 0n })
			);
			expect(checks).to.have.length(1);

			await collectGarbage();
			expect(watched.deref(), 'prev_tx still reachable').to.equal(undefined);

			checks[0].resolve('spent-or-missing');
			await new Promise((resolve) => setImmediate(resolve));
			expect(victim.getTempChannel(id), 'negotiation survives').to.not.equal(
				undefined
			);
		});

		it('launches no check for an input the budget refused', () => {
			const checks: IPendingCheck[] = [];
			const victim = makeManager('victim-refused', 0, {
				maxRetainedPeerPrevTxBytes: prevTx.length,
				verifyRemoteFundingInput: deferredVerifier(checks)
			});
			const id = acceptV2(victim, PEER_A, 'refused');
			expect(addInput(victim, PEER_A, id, 0n)).to.deep.equal([]);
			const refused = addInput(victim, PEER_A, id, 2n, makeLargePrevTx());
			expect(refused).to.have.length(1);
			expect(refused[0]).to.contain('node-wide budget');
			expect(checks).to.have.length(1);
		});
	});
});
