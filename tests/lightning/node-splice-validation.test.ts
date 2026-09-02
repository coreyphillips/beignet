import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import {
	Channel,
	ISpliceWalletInput
} from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState
} from '../../src/lightning/channel/types';
import { QuiescenceState } from '../../src/lightning/channel/quiescence';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../../src/lightning/channel/splice-weight';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import {
	InvalidSpliceError,
	ChannelFundingUnavailableError,
	ChannelFundingUnavailableCode,
	ISpliceRequestResult,
	SpliceRefusalCode
} from '../../src/lightning/node/types';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

const FUNDING_SATOSHIS = 1_000_000n;

function createTestNode(localFeatures?: FeatureFlags): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update('splice-validation-node')
		.digest();
	const node = new LightningNode({
		nodePrivateKey: crypto
			.createHash('sha256')
			.update('splice-validation-priv')
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		network: Network.REGTEST,
		...(localFeatures ? { localFeatures } : {})
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** Inject a synthetic NORMAL channel directly into the node's manager. */
function injectNormalChannel(node: LightningNode): Buffer {
	const seed = crypto
		.createHash('sha256')
		.update('splice-validation-chan')
		.digest();
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: FUNDING_SATOSHIS,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = ChannelState.NORMAL;
	state.fundingTxid = crypto.randomBytes(32);
	state.localBalanceMsat = FUNDING_SATOSHIS * 1000n;
	state.remoteBalanceMsat = 0n;
	const channel = new Channel(state);

	const manager = (node as any).channelManager;
	manager.channels.set(state.channelId!.toString('hex'), channel);
	manager.channelPeers.set(
		state.channelId!.toString('hex'),
		'02'.padEnd(66, 'ab')
	);
	return state.channelId!;
}

describe('LightningNode splice validation', function () {
	it('rejects a dust-level splice-out amount', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceOut(channelId, 500n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('dust floor');
		node.destroy();
	});

	it('rejects a splice-out whose fee meets or exceeds the amount', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// At 3000 sat/kw a 724-WU splice-out costs ~2172 sats — more than the
		// 2000 sats withdrawn (a footgun: more burned in fees than withdrawn).
		const result = node.spliceOut(channelId, 2000n, 3000);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('meets or exceeds the amount');
		node.destroy();
	});

	it('rejects a splice-out exceeding the spendable balance', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceOut(channelId, FUNDING_SATOSHIS, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('insufficient channel balance');
		node.destroy();
	});

	it('passes validation for a sane splice-out (fails later only on missing peer)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const dest = node.getSweepDestinationScript();
		const fee = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 0,
				destinationScriptLen: dest.length
			}),
			2500
		);
		expect(fee < 10_000n, 'fee sanity').to.be.true;
		const result = node.spliceOut(channelId, 10_000n, 2500);
		// Validation passed; the splice proceeds (initiateSplice succeeds — the
		// stfu is queued via message:outbound since no peer transport exists).
		expect(result.error ?? '').to.not.include('dust floor');
		expect(result.error ?? '').to.not.include('meets or exceeds');
		expect(result.error ?? '').to.not.include('insufficient channel balance');
		node.destroy();
	});

	it('rejects a dust-level splice-in amount before sourcing wallet inputs', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('dust floor');
		node.destroy();
	});

	it('reports a clear error when no splice-capable funding provider exists', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('selectSpliceInputs');
		node.destroy();
	});

	it('throws when destinationScript is provided but empty', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		expect(() =>
			node.spliceOut(channelId, 10_000n, 2500, Buffer.alloc(0))
		).to.throw('destinationScript must be a non-empty Buffer');
		node.destroy();
	});

	/**
	 * Issue #472: a splice refused for the caller's own arguments is typed, so
	 * the CLI layer answers 400 with this message rather than letting the
	 * daemon scrub it to a generic 500. An unknown channel is a state refusal
	 * and carries its own code.
	 */
	it('types the splice argument refusals and the unknown channel', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const argumentRefusals: Array<[string, () => unknown]> = [
			[
				'short channelId',
				(): unknown => node.spliceIn(Buffer.alloc(4), 10_000n, 2500)
			],
			['zero amount', (): unknown => node.spliceIn(channelId, 0n, 2500)],
			['negative amount', (): unknown => node.spliceOut(channelId, -1n, 2500)],
			[
				'empty destinationScript',
				(): unknown => node.spliceOut(channelId, 10_000n, 2500, Buffer.alloc(0))
			],
			[
				'non-standard destinationScript',
				(): unknown =>
					node.spliceOut(
						channelId,
						10_000n,
						2500,
						Buffer.from([0x6a, 0x01, 0x00])
					)
			]
		];
		for (const [label, run] of argumentRefusals) {
			expect(run, label).to.throw(InvalidSpliceError);
		}
		try {
			node.spliceQuote(Buffer.alloc(32, 0xee), 'out', 2500);
			expect.fail('expected the quote to be refused');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(ChannelFundingUnavailableError);
			expect((err as ChannelFundingUnavailableError).code).to.equal(
				ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND
			);
		}
		node.destroy();
	});

	it('records an external destinationScript for splice-out', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// A P2WPKH scriptPubKey (OP_0 <20-byte hash>) for an address the node
		// does not own, proving splice-out can pay an external destination.
		const externalScript = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto.randomBytes(20)
		]);
		const result = node.spliceOut(channelId, 10_000n, 2500, externalScript);
		expect(result.error ?? '').to.not.include('insufficient channel balance');
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		expect(channel._spliceOutDestination.script.equals(externalScript)).to.be
			.true;
		node.destroy();
	});

	it('enforces the negotiated dust floor on splice-out, not just the generic 546 (issue #389)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		// The peer negotiated a 1000-sat commitment dust limit, so every
		// output we add to the splice tx must clear 1000, not 546 — the
		// withdrawal destination included.
		channel.getFullState().remoteConfig.dustLimitSatoshis = 1_000n;
		expect(channel.spliceInteractiveTxDustFloor()).to.equal(1_000n);

		// 800 sats clears the generic 546-sat preflight but not this
		// channel's floor: the peer would refuse the tx_add_output and the
		// splice would abort only after the stfu round.
		const refused = node.spliceOut(channelId, 800n, 253);
		expect(refused.ok).to.be.false;
		expect(refused.error).to.match(/negotiated dust floor \(1000 sats\)/);

		// At the floor the new preflight admits it; whatever can still fail
		// later, it is never this arm.
		const atFloor = node.spliceOut(channelId, 1_000n, 253);
		expect(atFloor.error ?? '').to.not.include('negotiated dust floor');
		node.destroy();
	});

	it('prices the splice-out reserve at the post-splice capacity (issue #423)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		// Zero the stored reserve so only the derived post-capacity bound can
		// refuse: with 100k local of 1M capacity, withdrawing 92k leaves
		// ~7_816 sats, below 1% of the ~908k post-splice capacity.
		channel.getFullState().remoteConfig.channelReserveSatoshis = 0n;
		channel.getFullState().localBalanceMsat = 100_000_000n;
		channel.getFullState().remoteBalanceMsat = 900_000_000n;

		const refused = node.spliceOut(channelId, 92_000n, 253);
		expect(refused.ok).to.be.false;
		expect(refused.error).to.include('insufficient channel balance');

		// 80k leaves ~19_816 sats, above the ~9_198-sat derived bound: this
		// arm admits it (whatever can still fail later is never this arm).
		const admitted = node.spliceOut(channelId, 80_000n, 253);
		expect(admitted.error ?? '').to.not.include('insufficient channel balance');
		node.destroy();
	});

	it('does not pre-judge a splice-in reserve before input selection (issue #423 review)', function () {
		// The reserve rule arms only when the SELECTION emits a change
		// output, which is unknowable before selectSpliceInputs runs: a
		// below-reserve splice-in must reach the provider stage, not be
		// refused up-front.
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		channel.getFullState().localBalanceMsat = 2_000_000n;
		channel.getFullState().remoteBalanceMsat = 998_000_000n;
		const result = node.spliceIn(channelId, 3_000n);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('selectSpliceInputs');
		expect(result.error).to.not.include('reserve');
		node.destroy();
	});

	it('the splice-in reserve refusal is output-aware and runs after selection (issue #423)', async function () {
		const changeScript = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto.randomBytes(20)
		]);
		const fee = spliceFeeSats(
			estimateSpliceTxWeight({
				walletInputCount: 1,
				fundingScriptLen: 34,
				changeScriptLen: changeScript.length
			}),
			253
		);
		const makeInput = (value: bigint) => ({
			prevTx: Buffer.alloc(60),
			prevOutputIndex: 0,
			value,
			sequence: 0xfffffffd,
			signWitness: (): Buffer[] => [],
			confirmed: true
		});
		const lowBalance = (node: LightningNode): Buffer => {
			const channelId = injectNormalChannel(node);
			const channel = (node as any).channelManager.channels.get(
				channelId.toString('hex')
			);
			channel.getFullState().localBalanceMsat = 2_000_000n;
			channel.getFullState().remoteBalanceMsat = 998_000_000n;
			// The synthetic channel skips the handshake; a real NORMAL
			// channel always carries the peer basepoints the guard's funding
			// script derives from.
			channel.getFullState().remoteBasepoints = makeBasepoints(
				crypto.createHash('sha256').update('splice-validation-peer').digest()
			);
			return channelId;
		};

		// A change-emitting selection with 2k + 3k = 5k post balance, below
		// v2ReserveWeKeep(1_003_000) = 10_030: refused after selection, via
		// the async error surface.
		const refusingNode = createTestNode();
		const refusingErrors: string[] = [];
		refusingNode.on('node:error', (e: { message: string }) =>
			refusingErrors.push(e.message)
		);
		(refusingNode as any).fundingProvider = {
			selectSpliceInputs: async () => ({
				inputs: [makeInput(3_000n + fee + 2_000n)],
				changeScript
			})
		};
		const refusingId = lowBalance(refusingNode);
		expect(refusingNode.spliceIn(refusingId, 3_000n).ok).to.be.true;
		await new Promise((r) => setTimeout(r, 20));
		expect(
			refusingErrors.join('; '),
			'reserve refusal surfaced asynchronously'
		).to.match(/below the channel reserve/);
		refusingNode.destroy();

		// An exact-input selection emits no change output: same balances,
		// no refusal, the splice proceeds to quiescence.
		const admittingNode = createTestNode();
		const admittingErrors: string[] = [];
		admittingNode.on('node:error', (e: { message: string }) =>
			admittingErrors.push(e.message)
		);
		(admittingNode as any).fundingProvider = {
			selectSpliceInputs: async () => ({
				inputs: [makeInput(3_000n + fee)],
				changeScript
			})
		};
		const admittingId = lowBalance(admittingNode);
		expect(admittingNode.spliceIn(admittingId, 3_000n).ok).to.be.true;
		await new Promise((r) => setTimeout(r, 20));
		expect(
			admittingErrors.join('; '),
			'no reserve refusal for a no-change selection'
		).to.not.match(/below the channel reserve/);
		admittingNode.destroy();
	});

	it('spliceQuote maxAmountSats is exactly the largest amount spliceOut admits (issue #423)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		// A stored reserve below the derived band, where the old
		// current-capacity pricing understated the maximum: spliceOut prices
		// the reserve at the POST-splice capacity, so the quote must solve
		// against that same predicate.
		channel.getFullState().remoteConfig.channelReserveSatoshis = 0n;
		const quote = node.spliceQuote(channelId, 'out', 253);
		const max = BigInt(quote.maxAmountSats);
		// One above the advertised maximum is refused by the balance arm.
		const above = node.spliceOut(channelId, max + 1n, 253);
		expect(above.ok).to.be.false;
		expect(above.error).to.include('insufficient channel balance');
		// The advertised maximum itself passes it.
		const at = node.spliceOut(channelId, max, 253);
		expect(at.error ?? '').to.not.include('insufficient channel balance');
		// And it sits above the old current-capacity offer of
		// local - K(1M) - fee = 1M - 10_000 - fee.
		expect(Number(max)).to.be.greaterThan(
			Number(1_000_000n - 10_000n - BigInt(quote.feeSats))
		);
		node.destroy();
	});

	it('admits a splice-out exactly at the default 546-sat floor (issue #389)', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// The interactive-tx builder accepts an output AT the floor, so both
		// preflights must too: the generic arm is strict (< 546) and, on a
		// default-dust channel, the negotiated floor IS 546. Anything that
		// still fails later is never a dust arm.
		const atFloor = node.spliceOut(channelId, 546n, 253);
		expect(atFloor.error ?? '').to.not.include('dust floor');
		// One below stays refused.
		const below = node.spliceOut(channelId, 545n, 253);
		expect(below.ok).to.be.false;
		expect(below.error).to.include('below the dust floor');
		node.destroy();
	});
});

/**
 * Issue #618: a splice refusal is returned, not thrown, so a caller above the
 * engine has nothing but an English sentence to classify it by. Every arm now
 * carries a code, and the daemon answers each with a status of its own instead
 * of wrapping the refusal in a success envelope.
 */
describe('LightningNode splice refusal codes', function () {
	it('codes the unknown channel on both directions', function () {
		const node = createTestNode();
		const unknown = crypto.randomBytes(32);
		for (const result of [
			node.spliceIn(unknown, 100_000n, 253),
			node.spliceOut(unknown, 100_000n, 253)
		]) {
			expect(result.ok).to.be.false;
			expect(result.code).to.equal(SpliceRefusalCode.CHANNEL_NOT_FOUND);
			expect(result.error).to.include('Channel not found');
		}
		node.destroy();
	});

	it('codes the amount refusals as the caller argument they are', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// Below the generic dust floor, then a fee at or above the amount:
		// both are the caller's numbers, so both answer INVALID_PARAMS (400).
		expect(node.spliceOut(channelId, 500n, 253).code).to.equal(
			SpliceRefusalCode.INVALID_PARAMS
		);
		expect(node.spliceIn(channelId, 100n, 253).code).to.equal(
			SpliceRefusalCode.INVALID_PARAMS
		);
		expect(node.spliceOut(channelId, 2000n, 3000).code).to.equal(
			SpliceRefusalCode.INVALID_PARAMS
		);
		node.destroy();
	});

	it('codes a splice-out past the spendable balance', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceOut(channelId, FUNDING_SATOSHIS, 253);
		expect(result.code).to.equal(SpliceRefusalCode.INSUFFICIENT_BALANCE);
		node.destroy();
	});

	it('codes a splice-in with no wallet UTXO sourcing', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.code).to.equal(SpliceRefusalCode.FUNDING_PROVIDER_REQUIRED);
		node.destroy();
	});

	it('codes the pre-flight that reads the negotiated features', function () {
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		const node = createTestNode(spliceOnly);
		const channelId = injectNormalChannel(node);
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.code).to.equal(SpliceRefusalCode.SPLICING_NOT_NEGOTIATED);
		node.destroy();
	});

	it("carries the channel's own refusal instead of an undefined message", function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = (node as any).channelManager.channels.get(
			channelId.toString('hex')
		);
		channel._state.state = ChannelState.SHUTTING_DOWN;
		const result = node.spliceOut(channelId, 10_000n, 2500);
		expect(result.ok).to.be.false;
		expect(result.code).to.equal(SpliceRefusalCode.SPLICE_REFUSED);
		// The reason lived in the channel's ERROR action and never reached the
		// caller: the refusal arrived as `{ ok: false, error: undefined }`.
		expect(result.error).to.include('not in NORMAL state');
		node.destroy();
	});
});

/**
 * Issue #633: a splice the channel would start, only not yet. A pending abort
 * echo and a peer-owned quiescence session both end on their own, and coding
 * them SPLICE_REFUSED (a 409 isPermanentFailure calls permanent) told an
 * automated caller to give up on a splice that succeeds on the next attempt.
 */
describe('LightningNode transient splice refusals', function () {
	const channelOf = (node: LightningNode, channelId: Buffer): any =>
		(node as any).channelManager.channels.get(channelId.toString('hex'));

	/** Quiesce the channel from the peer's side, so the session is theirs. */
	const peerQuiesce = (node: LightningNode, channelId: Buffer): void => {
		const channel = channelOf(node, channelId);
		channel.handleStfuMessage({ channelId, initiator: true });
		expect(channel.isQuiescent(), 'peer stfu completed the handshake').to.be
			.true;
	};

	/**
	 * The latch initiateSpliceAbort leaves set until the peer echoes our
	 * tx_abort. Set directly: reaching it for real needs a live splice session
	 * and a peer to negotiate it with.
	 */
	const abortAwaitingEcho = (node: LightningNode, channelId: Buffer): void => {
		const channel = channelOf(node, channelId);
		channel._spliceAbortPending = true;
		expect(channel.isSpliceAbortPending()).to.be.true;
	};

	const p2wpkhScript = (): Buffer =>
		Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]);

	/** A caller-supplied splice input worth `valueSats`, paid to P2WPKH. */
	const makeInput = (valueSats: number): ISpliceWalletInput => {
		const prevTx = new bitcoin.Transaction();
		prevTx.version = 2;
		prevTx.addInput(crypto.randomBytes(32), 0);
		prevTx.addOutput(p2wpkhScript(), valueSats);
		return {
			prevTx: prevTx.toBuffer(),
			prevOutputIndex: 0,
			value: BigInt(valueSats),
			sequence: 0xfffffffd,
			signWitness: (): Buffer[] => [Buffer.alloc(71, 1), Buffer.alloc(33, 2)]
		};
	};

	/** The two request paths that hand the refusal back to their caller. */
	const REQUESTS: Array<
		[string, (node: LightningNode, channelId: Buffer) => ISpliceRequestResult]
	> = [
		[
			'spliceOut',
			(node, channelId): ISpliceRequestResult =>
				node.spliceOut(channelId, 50_000n, 253)
		],
		[
			'spliceInWithInputs',
			(node, channelId): ISpliceRequestResult =>
				node.spliceInWithInputs(
					channelId,
					100_000n,
					[makeInput(200_000)],
					p2wpkhScript()
				)
		]
	];

	it('codes a peer-owned quiescence session as busy on both paths', function () {
		for (const [name, request] of REQUESTS) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			peerQuiesce(node, channelId);
			const result = request(node, channelId);
			expect(result.ok, name).to.be.false;
			expect(result.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			// The message already said to retry; the code said not to.
			expect(result.error, name).to.include('retry after it ends');
			node.destroy();
		}
	});

	it('codes an unacknowledged splice abort as busy on both paths', function () {
		for (const [name, request] of REQUESTS) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			abortAwaitingEcho(node, channelId);
			const result = request(node, channelId);
			expect(result.ok, name).to.be.false;
			expect(result.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			expect(result.error, name).to.include('not yet acknowledged');
			node.destroy();
		}
	});

	it('leaves a refusal that cannot clear coded permanent', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		channelOf(node, channelId)._state.state = ChannelState.SHUTTING_DOWN;
		const result = node.spliceOut(channelId, 50_000n, 253);
		expect(result.code).to.equal(SpliceRefusalCode.SPLICE_REFUSED);
		node.destroy();
	});

	/**
	 * Issue #639: an ordinary peer reconnect. markForReestablish wraps the
	 * NORMAL channel in AWAITING_REESTABLISH, and the same request that was
	 * refused starts the splice once handleReestablish unwraps it.
	 */
	it('codes a reconnecting channel as busy, then starts on both paths', function () {
		for (const [name, request] of REQUESTS) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			const channel = channelOf(node, channelId);
			channel.markForReestablish();
			expect(channel.getState(), name).to.equal(
				ChannelState.AWAITING_REESTABLISH
			);

			const refused = request(node, channelId);
			expect(refused.ok, name).to.be.false;
			expect(refused.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			expect(refused.error, name).to.include('reconnecting');

			// Reestablishment done: the wrapped state comes back, and the
			// identical request is the one that used to be called permanent.
			channel._state.state = channel._state.preReestablishState;
			channel._state.preReestablishState = null;
			expect(request(node, channelId).ok, name).to.be.true;
			node.destroy();
		}
	});

	/** An offered HTLC still awaiting its commitment round on both sides. */
	const settlingHtlc = (node: LightningNode, channelId: Buffer): void => {
		channelOf(node, channelId)
			.getFullState()
			.htlcs.set('offered-0', {
				id: 0n,
				direction: HtlcDirection.OFFERED,
				amountMsat: 5_000_000n,
				paymentHash: crypto.randomBytes(32),
				cltvExpiry: 500,
				state: HtlcState.PENDING,
				onionRoutingPacket: Buffer.alloc(1366)
			});
	};

	/** A funding provider whose selection resolves, counting its calls. */
	const withSpliceProvider = (node: LightningNode): { selections: number } => {
		const calls = { selections: 0 };
		(node as any).fundingProvider = {
			selectSpliceInputs: async () => {
				calls.selections++;
				return { inputs: [makeInput(200_000)], changeScript: p2wpkhScript() };
			}
		};
		return calls;
	};

	/**
	 * Issue #642: spliceIn sources its wallet inputs asynchronously, so a
	 * refusal raised after the selection reached the caller only as a
	 * node:error. The route had already answered 200, and the 503 the contract
	 * tells a caller to retry on never happened.
	 */
	it('codes a busy splice-in before the wallet selection runs', async function () {
		const busyStates: Array<
			[string, (node: LightningNode, channelId: Buffer) => void, RegExp]
		> = [
			['peer quiescence', peerQuiesce, /retry after it ends/],
			['abort awaiting echo', abortAwaitingEcho, /not yet acknowledged/],
			[
				'reconnecting',
				(node, channelId): void =>
					channelOf(node, channelId).markForReestablish(),
				/reconnecting/
			],
			['settling HTLCs', settlingHtlc, /pending HTLCs/],
			[
				'peer stfu still draining',
				(node, channelId): void => {
					settlingHtlc(node, channelId);
					const channel = channelOf(node, channelId);
					channel.handleStfuMessage({ channelId, initiator: true });
					expect(
						channel.getQuiescenceState(),
						'the peer stfu latched, its reply owed'
					).to.equal(QuiescenceState.RECEIVED_STFU);
				},
				/retry after it ends/
			],
			[
				'a request already parked on our stfu',
				(node, channelId): void => {
					expect(
						node.spliceOut(channelId, 40_000n, 253).ok,
						'the first request parks on the stfu it sent'
					).to.be.true;
				},
				/already awaiting quiescence/
			]
		];
		for (const [name, makeBusy, message] of busyStates) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			const provider = withSpliceProvider(node);
			makeBusy(node, channelId);

			const result = node.spliceIn(channelId, 100_000n, 253);
			expect(result.ok, name).to.be.false;
			expect(result.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			expect(result.error, name).to.match(message);
			// And no coins were selected for a splice that never started.
			await new Promise((r) => setTimeout(r, 10));
			expect(provider.selections, name).to.equal(0);
			node.destroy();
		}
	});

	/**
	 * Issue #656: the same latched handshake on the two synchronous paths. The
	 * request used to park on it, but the reply that completes a peer-initiated
	 * stfu goes out from _maybeAnswerOwedStfu, which has no deferred-splice
	 * hook, so an accepted request sat there for the life of the peer's session
	 * with its wallet inputs pledged.
	 */
	it('codes a peer stfu that is still draining as busy on both paths', function () {
		for (const [name, request] of REQUESTS) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			const channel = channelOf(node, channelId);
			settlingHtlc(node, channelId);
			channel.handleStfuMessage({ channelId, initiator: true });
			expect(channel.getQuiescenceState(), name).to.equal(
				QuiescenceState.RECEIVED_STFU
			);

			const result = request(node, channelId);
			expect(result.ok, name).to.be.false;
			expect(result.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			expect(result.error, name).to.include('retry after it ends');
			expect(channel._pendingSplice, name).to.be.null;
			// The refused request's direction dies with it, so the coins are
			// freed and nothing leaks into a later splice.
			expect(channel._spliceOutDestination, name).to.be.null;
			expect(channel._spliceInInputs, name).to.be.null;

			// The drain completes the peer's handshake and does nothing else.
			channel.getFullState().htlcs.delete('offered-0');
			const drained = channel._maybeAnswerOwedStfu();
			expect(
				drained.filter(
					(a: { type: ChannelActionType; messageType?: MessageType }) =>
						a.type === ChannelActionType.ERROR ||
						a.messageType === MessageType.SPLICE
				),
				name
			).to.be.empty;
			expect(channel.getQuiescenceState(), name).to.equal(
				QuiescenceState.QUIESCENT
			);
			expect(channel._pendingSplice, name).to.be.null;
			node.destroy();
		}
	});

	/**
	 * Issue #655: a request parked on our own unanswered stfu used to be
	 * replaced by the next one, and both callers were told their splice had
	 * started. Only the later request ran, with the earlier one's direction
	 * already overwritten on the channel.
	 */
	it('codes a request displacing one parked on our stfu as busy on both paths', function () {
		for (const [name, request] of REQUESTS) {
			const node = createTestNode();
			const channelId = injectNormalChannel(node);
			const channel = channelOf(node, channelId);

			// The first request drives quiescence and parks until the peer answers.
			const destination = p2wpkhScript();
			expect(node.spliceOut(channelId, 40_000n, 253, destination).ok, name).to
				.be.true;
			expect(channel.isQuiescing(), name).to.be.true;
			const parked = channel._pendingSplice;
			expect(parked, name).to.not.be.null;

			const second = request(node, channelId);
			expect(second.ok, name).to.be.false;
			expect(second.code, name).to.equal(SpliceRefusalCode.SPLICE_BUSY);
			expect(second.error, name).to.include('already awaiting quiescence');
			// The parked request is untouched, and the refused one's direction
			// dies with it rather than sitting on the channel.
			expect(channel._pendingSplice, name).to.equal(parked);
			expect(channel._spliceOutDestination, name).to.be.null;
			expect(channel._spliceInInputs, name).to.be.null;

			// The peer's stfu fires the FIRST request, with the direction that
			// request was made with.
			const actions = channel.handleStfuMessage({
				channelId,
				initiator: false
			});
			expect(
				actions.some(
					(a: { messageType?: MessageType }) =>
						a.messageType === MessageType.SPLICE
				),
				name
			).to.be.true;
			expect(channel._spliceInInputs, name).to.be.null;
			expect(channel._spliceOutDestination.script.equals(destination), name).to
				.be.true;
			expect(channel._spliceOutDestination.sats, name).to.equal(40_000n);
			node.destroy();
		}
	});

	/**
	 * Issue #655, the asynchronous half: spliceIn selects its wallet inputs
	 * before anything reaches the channel, so a second caller passed the busy
	 * check while the first was still selecting. Both were told ok and the
	 * request whose selection resolved second was refused with its answer long
	 * gone.
	 */
	it('refuses a second splice-in while the first is still selecting inputs', async function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const errors: string[] = [];
		node.on('node:error', (e: { message: string }) => errors.push(e.message));
		let release: () => void = () => undefined;
		const held = new Promise<void>((r) => (release = r));
		let selections = 0;
		(node as any).fundingProvider = {
			selectSpliceInputs: async () => {
				selections++;
				await held;
				return { inputs: [makeInput(200_000)], changeScript: p2wpkhScript() };
			}
		};

		expect(node.spliceIn(channelId, 100_000n, 253).ok).to.be.true;
		const second = node.spliceIn(channelId, 120_000n, 253);
		expect(second.ok).to.be.false;
		expect(second.code).to.equal(SpliceRefusalCode.SPLICE_BUSY);
		expect(second.error).to.include('still selecting its inputs');
		expect(selections, 'no coins selected for the refused request').to.equal(1);
		// Returned, never emitted: SPLICE_IN_FAILED is scoped by channel alone,
		// so an emission here would reject the spliceInAndWait belonging to the
		// request that survives.
		expect(errors).to.deep.equal([]);

		release();
		await new Promise((r) => setTimeout(r, 20));
		const channel = channelOf(node, channelId);
		expect(channel.isQuiescing(), 'the first request drove the handshake').to.be
			.true;
		expect(channel._pendingSplice.relativeSatoshis).to.equal(100_000n);
		expect(errors, 'and it failed for nothing').to.deep.equal([]);
		node.destroy();
	});

	it('still starts a splice-in on a channel that is ready', async function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const provider = withSpliceProvider(node);
		expect(node.spliceIn(channelId, 100_000n, 253).ok).to.be.true;
		await new Promise((r) => setTimeout(r, 20));
		expect(provider.selections, 'the selection ran').to.equal(1);
		node.destroy();
	});

	it('keeps a channel that closed while marked coded permanent', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		const channel = channelOf(node, channelId);
		channel.markForReestablish();
		// Nothing clears preReestablishState on the way out, so the wrapped
		// NORMAL outlives the channel: the marker is what says it comes back.
		channel._state.state = ChannelState.CLOSED;
		const result = node.spliceOut(channelId, 50_000n, 253);
		expect(result.code).to.equal(SpliceRefusalCode.SPLICE_REFUSED);
		node.destroy();
	});
});

describe('LightningNode peerSupportsSplicing', function () {
	const PEER = '02'.padEnd(66, 'ab');
	const withInit = (node: LightningNode, features: FeatureFlags | null) => {
		(node as any).peerManager = {
			getPeer: () =>
				features === null ? undefined : { getRemoteInit: () => ({ features }) },
			destroy: () => {}
		};
	};

	it('is null when there is nothing to read', function () {
		const node = createTestNode();
		expect(node.peerSupportsSplicing(PEER), 'no peer manager yet').to.be.null;
		withInit(node, null);
		expect(node.peerSupportsSplicing(PEER), 'peer not connected').to.be.null;
		node.destroy();
	});

	it('reads the negotiated features, not a guess', function () {
		const node = createTestNode();
		const both = new FeatureFlags();
		both.setOptional(Feature.QUIESCE);
		both.setOptional(Feature.SPLICE);
		withInit(node, both);
		expect(node.peerSupportsSplicing(PEER)).to.be.true;

		// splice without quiesce is not splicing support: stfu is the first
		// message of every splice, so both bits are required, same as the
		// validation this mirrors.
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		withInit(node, spliceOnly);
		expect(node.peerSupportsSplicing(PEER)).to.be.false;

		withInit(node, new FeatureFlags());
		expect(node.peerSupportsSplicing(PEER)).to.be.false;
		node.destroy();
	});

	it('is what the splice pre-flight enforces: an LND-shaped peer refuses', function () {
		const node = createTestNode();
		const channelId = injectNormalChannel(node);
		// LND advertises neither option_splice nor option_quiesce.
		withInit(node, new FeatureFlags());
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('not negotiated');
		node.destroy();
	});

	// Negotiation is mutual. localFeatures is caller configuration, so a node
	// configured without splicing must not report a channel spliceable just
	// because the peer across it is willing: the daemon would advertise a
	// capability its own init never offered, and the splice would die at stfu.
	it('is false when the remote is willing but our own features are not', () => {
		const remote = new FeatureFlags();
		remote.setOptional(Feature.QUIESCE);
		remote.setOptional(Feature.SPLICE);

		const noQuiesce = new FeatureFlags();
		noQuiesce.setOptional(Feature.SPLICE);
		const nodeNoQuiesce = createTestNode(noQuiesce);
		withInit(nodeNoQuiesce, remote);
		expect(nodeNoQuiesce.peerSupportsSplicing(PEER)).to.be.false;
		nodeNoQuiesce.destroy();

		const noSplice = new FeatureFlags();
		noSplice.setOptional(Feature.QUIESCE);
		const nodeNoSplice = createTestNode(noSplice);
		withInit(nodeNoSplice, remote);
		expect(nodeNoSplice.peerSupportsSplicing(PEER)).to.be.false;
		nodeNoSplice.destroy();

		// And the default features do negotiate it, so a stock node against a
		// willing peer still answers true.
		const stock = createTestNode();
		withInit(stock, remote);
		expect(stock.peerSupportsSplicing(PEER)).to.be.true;
		stock.destroy();
	});

	// A missing remote init means unknown only when the local half is capable.
	// Local incapability is a certainty no amount of remote information can
	// overturn, so it must not hide behind null while the peer is offline.
	it('local incapability is false even with no remote init to read', () => {
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		const noQuiesce = createTestNode(spliceOnly);
		expect(noQuiesce.peerSupportsSplicing(PEER)).to.be.false;
		noQuiesce.destroy();

		const quiesceOnly = new FeatureFlags();
		quiesceOnly.setOptional(Feature.QUIESCE);
		const noSplice = createTestNode(quiesceOnly);
		expect(noSplice.peerSupportsSplicing(PEER)).to.be.false;
		noSplice.destroy();

		const both = new FeatureFlags();
		both.setOptional(Feature.QUIESCE);
		both.setOptional(Feature.SPLICE);
		const capable = createTestNode(both);
		expect(
			capable.peerSupportsSplicing(PEER),
			'a capable node with no init to read is genuinely unknown'
		).to.be.null;
		capable.destroy();
	});

	it('the pre-flight refuses a splice on local incapability alone', () => {
		const spliceOnly = new FeatureFlags();
		spliceOnly.setOptional(Feature.SPLICE);
		const node = createTestNode(spliceOnly);
		const channelId = injectNormalChannel(node);
		// No peer manager stub at all: the peer is unreachable, and the
		// refusal must not wait to hear from it.
		const result = node.spliceIn(channelId, 100_000n, 253);
		expect(result.ok).to.be.false;
		expect(result.error).to.include('not negotiated');
		node.destroy();
	});
});
