/**
 * Channel send (issue #1922, docs/MULTI-CHANNEL-SPLICE-OUT.md section 7):
 * BeignetNode.quoteChannelSend picks one channel or a composite, the quote is
 * executed once, and the composite's amount plus fee rides the spend
 * reservation (reserved at start, charged at RELEASED, released at ABORTED).
 *
 * Unit cases drive BeignetNode over a stubbed engine (Object.create keeps the
 * real prototype methods, none of the node boot). Route cases boot the daemon
 * offline: with no channels every quote refuses, which is enough to pin the
 * envelopes, the scopes being covered by auth-scopes.test.ts.
 */
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import {
	BeignetNode,
	CHANNEL_SEND_QUOTE_TTL_MS
} from '../../src/cli/beignet-node';
import { BeignetErrorCode } from '../../src/cli/errors';
import type { ChannelSendQuote, ChannelSendStatus } from '../../src/cli/types';
import type { ICompositeSpliceRecord } from '../../src/lightning/channel/composite-splice-record';
import {
	COMPOSITE_SPLICE_RETENTION_MS,
	CompositeSpliceRefusalCode
} from '../../src/lightning/node/composite-splice-engine';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// secp256k1 generator point, compressed: a valid pubkey for address fixtures.
const PUBKEY = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);
const REGTEST_ADDRESS = bitcoin.payments.p2wpkh({
	pubkey: PUBKEY,
	network: bitcoin.networks.regtest
}).address!;

const CHANNEL_A = 'aa'.repeat(32);
const CHANNEL_B = 'bb'.repeat(32);
const PEER = '02' + '11'.repeat(32);
// Records hold txids in internal byte order and the API shows display order;
// non-palindromic fixtures make the reversal part of what the tests pin.
const TXID_INTERNAL = '0a1b2c3d'.repeat(8);
const TXID2_INTERNAL = '4e5f6071'.repeat(8);
function reverseHex(hex: string): string {
	return Buffer.from(hex, 'hex').reverse().toString('hex');
}

interface IFakeChannel {
	id: string;
	spendableSats: number;
	maxAmountSats: number;
	feeSats: number;
	capacitySats: number;
	/** The negotiated interactive-tx dust floor; 546 when unset. */
	dustFloorSats?: number;
}

interface IFakeEngine {
	channels: IFakeChannel[];
	spliceOutCalls: Array<{ channelId: string; amountSats: bigint }>;
	spliceOutResult: { ok: boolean; error?: string };
	plan: { ok: boolean; [k: string]: unknown };
	start: { ok: boolean; [k: string]: unknown };
	startCalls: number;
	records: Map<string, ICompositeSpliceRecord>;
	abortResult: {
		ok: boolean;
		error?: string;
		code?: CompositeSpliceRefusalCode;
	};
	getChannelManager: () => unknown;
	peerSupportsSplicing: () => boolean | null;
	spliceQuote: (
		id: Buffer,
		dir: string,
		feerate: number
	) => { maxAmountSats: number; feeSats: number; spendableSats: number };
	planCompositeSpliceOut: () => Promise<unknown>;
	startCompositeSpliceOut: () => Promise<unknown>;
	spliceOut: (
		id: Buffer,
		amountSats: bigint
	) => { ok: boolean; error?: string };
	getCompositeSplice: (id: Buffer) => ICompositeSpliceRecord | null;
	listCompositeSplices: () => ICompositeSpliceRecord[];
	abortCompositeSplice: () => {
		ok: boolean;
		error?: string;
		code?: CompositeSpliceRefusalCode;
	};
}

interface IFake {
	_dailySpendLimitSats: number | undefined;
	_maxPaymentSats: number | undefined;
	_dailySpentSats: number;
	_dailySpentLightningSats: number;
	_dailySpentOnchainSats: number;
	_pendingSpendSats: number;
	_dailySpendResetTime: number;
	_asyncSpendClaims: Map<string, unknown>;
	_channelSendQuotes?: Map<string, { quote: ChannelSendQuote }>;
	getBitcoinNetwork: () => unknown;
	log: () => void;
	node: IFakeEngine;
	quoteChannelSend: BeignetNode['quoteChannelSend'];
	executeChannelSend: BeignetNode['executeChannelSend'];
	getChannelSend: BeignetNode['getChannelSend'];
	listChannelSends: BeignetNode['listChannelSends'];
	abortChannelSend: BeignetNode['abortChannelSend'];
	on: BeignetNode['on'];
	_onCompositeSpliceStage: (event: {
		id: Buffer;
		stage: string;
		txid?: Buffer;
		reason?: string;
	}) => void;
	_onSingleChannelSendSpliceEvent: (
		channelId: string,
		stage: 'LOCKED' | 'ABORTED',
		detail: { txid?: string; reason?: string }
	) => void;
	_channelSends?: Map<string, { status: ChannelSendStatus; endedAt?: number }>;
}

function compositeRecord(
	id: string,
	stage: ICompositeSpliceRecord['stage']
): ICompositeSpliceRecord {
	return {
		id,
		stage,
		channels: [
			{
				channelId: CHANNEL_A,
				peerPubkey: PEER,
				fundingTxid: '33'.repeat(32),
				fundingOutputIndex: 0,
				debitSats: '700000',
				feeSats: '400',
				oldCapacitySats: '1000000',
				newCapacitySats: '299600',
				inputSerialId: '0',
				fundingOutputSerialId: '4'
			},
			{
				channelId: CHANNEL_B,
				peerPubkey: PEER,
				fundingTxid: '44'.repeat(32),
				fundingOutputIndex: 0,
				debitSats: '500000',
				feeSats: '300',
				oldCapacitySats: '1000000',
				newCapacitySats: '499700',
				inputSerialId: '2',
				fundingOutputSerialId: '6'
			}
		],
		destinationScript: '0014' + '55'.repeat(20),
		destinationSerialId: '8',
		amountSats: '1200000',
		feeSats: '700',
		feeratePerkw: 1000,
		locktime: 0,
		createdAt: 1_700_000_000_000,
		updatedAt: 1_700_000_000_000
	};
}

function fakeNode(opts: {
	limitSats?: number;
	maxPaymentSats?: number;
	channels: IFakeChannel[];
}): IFake {
	const fake = Object.create(BeignetNode.prototype) as unknown as IFake;
	fake._dailySpendLimitSats = opts.limitSats;
	fake._maxPaymentSats = opts.maxPaymentSats;
	fake._dailySpentSats = 0;
	fake._dailySpentLightningSats = 0;
	fake._dailySpentOnchainSats = 0;
	fake._pendingSpendSats = 0;
	fake._dailySpendResetTime = Date.now() + 24 * 60 * 60 * 1000;
	fake._asyncSpendClaims = new Map();
	fake.getBitcoinNetwork = (): unknown => bitcoin.networks.regtest;
	fake.log = (): void => undefined;
	const engine: IFakeEngine = {
		channels: opts.channels,
		spliceOutCalls: [],
		spliceOutResult: { ok: true },
		plan: {
			ok: false,
			error: 'no plan configured',
			code: CompositeSpliceRefusalCode.INSUFFICIENT_BALANCE
		},
		start: {
			ok: false,
			error: 'no start configured',
			code: CompositeSpliceRefusalCode.BUSY
		},
		startCalls: 0,
		records: new Map(),
		abortResult: { ok: true },
		getChannelManager: () => ({
			listChannels: () =>
				engine.channels.map((c) => ({
					getChannelId: () => Buffer.from(c.id, 'hex'),
					getState: () => 'NORMAL',
					spliceBusyReason: () => null,
					getFullState: () => ({ spliceInFlight: null }),
					getFundingSatoshis: () => BigInt(c.capacitySats),
					spliceInteractiveTxDustFloor: () => BigInt(c.dustFloorSats ?? 546)
				})),
			getPeerForChannel: () => PEER
		}),
		peerSupportsSplicing: () => true,
		spliceQuote: (id) => {
			const c = engine.channels.find((x) => x.id === id.toString('hex'))!;
			return {
				maxAmountSats: c.maxAmountSats,
				feeSats: c.feeSats,
				spendableSats: c.spendableSats
			};
		},
		planCompositeSpliceOut: async () => engine.plan,
		startCompositeSpliceOut: async () => {
			engine.startCalls++;
			return engine.start;
		},
		spliceOut: (id, amountSats) => {
			engine.spliceOutCalls.push({ channelId: id.toString('hex'), amountSats });
			return engine.spliceOutResult;
		},
		getCompositeSplice: (id) => engine.records.get(id.toString('hex')) ?? null,
		listCompositeSplices: () => [...engine.records.values()],
		abortCompositeSplice: () => engine.abortResult
	};
	fake.node = engine;
	return fake;
}

const compositePlan = (): { ok: true; plan: unknown } => ({
	ok: true,
	plan: {
		destinationScript: Buffer.alloc(22),
		amountSats: 1_200_000n,
		feeSats: 700n,
		feeratePerkw: 1000,
		locktime: 0,
		weight: 1400,
		channels: [
			{
				channelId: Buffer.from(CHANNEL_A, 'hex'),
				peerPubkey: PEER,
				debitSats: 700_000n,
				feeSats: 400n,
				oldCapacitySats: 1_000_000n,
				newCapacitySats: 299_600n,
				maxDebitSats: 700_000n
			},
			{
				channelId: Buffer.from(CHANNEL_B, 'hex'),
				peerPubkey: PEER,
				debitSats: 500_000n,
				feeSats: 300n,
				oldCapacitySats: 1_000_000n,
				newCapacitySats: 499_700n,
				maxDebitSats: 900_000n
			}
		],
		skipped: [
			{
				channelId: Buffer.from('cc'.repeat(32), 'hex'),
				reason: 'peer is not connected'
			}
		]
	}
});

async function refusal(
	run: () => Promise<unknown>
): Promise<{ code?: string; message: string }> {
	try {
		await run();
	} catch (err) {
		return err as { code?: string; message: string };
	}
	throw new Error('expected a refusal');
}

describe('Channel send (issue #1922)', function () {
	describe('BeignetNode over a stubbed engine', function () {
		const twoChannels: IFakeChannel[] = [
			{
				id: CHANNEL_A,
				spendableSats: 900_000,
				maxAmountSats: 850_000,
				feeSats: 180,
				capacitySats: 1_000_000
			},
			{
				id: CHANNEL_B,
				spendableSats: 500_000,
				maxAmountSats: 450_000,
				feeSats: 180,
				capacitySats: 600_000
			}
		];

		it('quotes a single-channel send from the channel with the largest spendable balance when one covers amount plus fee', async function () {
			const fake = fakeNode({ channels: twoChannels });
			const quote = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			expect(quote.kind).to.equal('single');
			expect(quote.channels).to.have.length(1);
			expect(quote.channels[0].channelId).to.equal(CHANNEL_A);
			expect(quote.channels[0].debitSats).to.equal(300_000);
			expect(quote.feeSats).to.equal(180);
			expect(quote.totalSats).to.equal(300_180);
			expect(quote.channels[0].newCapacitySats).to.equal(1_000_000 - 300_180);
			expect(quote.skipped).to.deep.equal([]);
			expect(quote.quoteId).to.match(/^[0-9a-f]{64}$/);
			expect(quote.expiresAt).to.be.closeTo(
				Date.now() + CHANNEL_SEND_QUOTE_TTL_MS,
				2_000
			);
		});

		it('quotes a composite when no single channel covers the amount', async function () {
			const fake = fakeNode({ channels: twoChannels });
			fake.node.plan = compositePlan();
			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			expect(quote.kind).to.equal('composite');
			expect(quote.channels.map((c) => c.channelId)).to.deep.equal([
				CHANNEL_A,
				CHANNEL_B
			]);
			expect(quote.channels[0]).to.deep.equal({
				channelId: CHANNEL_A,
				debitSats: 700_000,
				feeSats: 400,
				oldCapacitySats: 1_000_000,
				newCapacitySats: 299_600
			});
			expect(quote.feeSats).to.equal(700);
			expect(quote.totalSats).to.equal(1_200_700);
			expect(quote.skipped).to.deep.equal([
				{ channelId: 'cc'.repeat(32), reason: 'peer is not connected' }
			]);
		});

		it('refuses a bad address, amount or feerate, a plan refusal with its reasons, and a spend over the limits', async function () {
			const fake = fakeNode({
				channels: twoChannels,
				limitSats: 1_000_000,
				maxPaymentSats: 800_000
			});
			expect(
				(await refusal(() => fake.quoteChannelSend('', 300_000, 1000))).code
			).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend('not-an-address', 300_000, 1000)
					)
				).code
			).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(
				(await refusal(() => fake.quoteChannelSend(REGTEST_ADDRESS, 0, 1000)))
					.code
			).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 10)
					)
				).code
			).to.equal(BeignetErrorCode.INVALID_PARAMS);
			// Over the per-payment limit, single path.
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend(REGTEST_ADDRESS, 820_000, 1000)
					)
				).code
			).to.equal(BeignetErrorCode.SPENDING_LIMIT_EXCEEDED);
			// The composite plan's refusal keeps its code and carries the reasons.
			fake.node.plan = {
				ok: false,
				error:
					'the eligible channels cannot cover 1200000 sats plus fees at 1000 sat/kw',
				code: CompositeSpliceRefusalCode.INSUFFICIENT_BALANCE,
				skipped: [
					{
						channelId: Buffer.from(CHANNEL_B, 'hex'),
						reason: 'funding is not confirmed (zero-conf channel)'
					}
				]
			};
			const refused = await refusal(() =>
				fake.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000)
			);
			expect(refused.code).to.equal(BeignetErrorCode.INSUFFICIENT_BALANCE);
			expect(refused.message).to.match(
				/skipped: bbbbbbbbbbbb: funding is not confirmed/
			);
			fake.node.plan = {
				ok: false,
				error: 'a composite splice is already live',
				code: CompositeSpliceRefusalCode.BUSY
			};
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000)
					)
				).code
			).to.equal(BeignetErrorCode.SPLICE_BUSY);
			fake.node.plan = {
				ok: false,
				error: 'storage',
				code: CompositeSpliceRefusalCode.STORAGE_REQUIRED
			};
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000)
					)
				).code
			).to.equal(BeignetErrorCode.NOT_PERSISTED);
			// Over the daily limit on a composite that would otherwise plan.
			fake.node.plan = compositePlan();
			fake._maxPaymentSats = undefined;
			fake._dailySpentSats = 0;
			fake._dailySpendLimitSats = 1_000_000;
			expect(
				(
					await refusal(() =>
						fake.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000)
					)
				).code
			).to.equal(BeignetErrorCode.SPENDING_LIMIT_EXCEEDED);
		});

		it('executes a single-channel quote through spliceOut, records the spend once, and repeats nothing on the same quote', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			const stages: string[] = [];
			fake.on('channel-send:stage', (d: { stage: string }) =>
				stages.push(d.stage)
			);
			const quote = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			const run = await fake.executeChannelSend(quote.quoteId);
			expect(run.kind).to.equal('single');
			expect(run.stage).to.equal('STARTED');
			expect(run.channelId).to.equal(CHANNEL_A);
			expect(run.id).to.equal(quote.quoteId);
			expect(fake.node.spliceOutCalls).to.deep.equal([
				{ channelId: CHANNEL_A, amountSats: 300_000n }
			]);
			expect(fake._dailySpentSats, 'amount plus fee recorded').to.equal(
				300_180
			);
			expect(fake._dailySpentOnchainSats).to.equal(300_180);
			expect(fake._pendingSpendSats).to.equal(0);
			expect(stages).to.deep.equal(['STARTED']);
			const again = await fake.executeChannelSend(quote.quoteId);
			expect(again.id).to.equal(run.id);
			expect(fake.node.spliceOutCalls, 'no second splice').to.have.length(1);
			expect(fake._dailySpentSats, 'no second charge').to.equal(300_180);
			expect(fake.getChannelSend(quote.quoteId)!.stage).to.equal('STARTED');
			expect(fake.listChannelSends().map((s) => s.id)).to.deep.equal([
				quote.quoteId
			]);
		});

		it('an engine refusal of the single splice is thrown with its code and records no spend', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			fake.node.spliceOutResult = {
				ok: false,
				error: 'insufficient channel balance for splice-out'
			};
			const quote = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			const refused = await refusal(() =>
				fake.executeChannelSend(quote.quoteId)
			);
			expect(refused.code).to.equal(BeignetErrorCode.SPLICE_REFUSED);
			expect(fake._dailySpentSats).to.equal(0);
			// The quote is still there for a retry.
			fake.node.spliceOutResult = { ok: true };
			const run = await fake.executeChannelSend(quote.quoteId);
			expect(run.stage).to.equal('STARTED');
		});

		it('a composite reserves amount plus fee, charges it at RELEASED and keeps the charge through CONFLICTED', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			fake.node.plan = compositePlan();
			const compositeId = '77'.repeat(32);
			fake.node.start = {
				ok: true,
				id: Buffer.from(compositeId, 'hex'),
				plan: compositePlan().plan
			};
			fake.node.records.set(
				compositeId,
				compositeRecord(compositeId, 'NEGOTIATING')
			);
			const stages: Array<{
				id: string;
				stage: string;
				compositeId?: string;
				txid?: string;
			}> = [];
			fake.on(
				'channel-send:stage',
				(d: {
					id: string;
					stage: string;
					compositeId?: string;
					txid?: string;
				}) => stages.push(d)
			);

			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			const run = await fake.executeChannelSend(quote.quoteId);
			expect(run.kind).to.equal('composite');
			expect(run.compositeId).to.equal(compositeId);
			expect(run.stage).to.equal('NEGOTIATING');
			expect(run.record!.id).to.equal(compositeId);
			expect(fake.node.startCalls).to.equal(1);
			expect(fake._pendingSpendSats, 'reserved, not spent').to.equal(1_200_700);
			expect(fake._dailySpentSats).to.equal(0);

			fake.node.records.set(compositeId, {
				...compositeRecord(compositeId, 'RELEASED'),
				txid: TXID_INTERNAL
			});
			fake._onCompositeSpliceStage({
				id: Buffer.from(compositeId, 'hex'),
				stage: 'RELEASED',
				txid: Buffer.from(TXID_INTERNAL, 'hex')
			});
			expect(fake._pendingSpendSats, 'reservation converted').to.equal(0);
			expect(fake._dailySpentSats, 'charged once at RELEASED').to.equal(
				1_200_700
			);
			expect(fake._dailySpentOnchainSats).to.equal(1_200_700);
			const status = fake.getChannelSend(quote.quoteId)!;
			expect(status.stage).to.equal('RELEASED');
			expect(status.txid, 'display order').to.equal(reverseHex(TXID_INTERNAL));

			fake._onCompositeSpliceStage({
				id: Buffer.from(compositeId, 'hex'),
				stage: 'CONFLICTED',
				reason: 'channel left'
			});
			expect(fake._dailySpentSats, 'an uncertain outcome stays spent').to.equal(
				1_200_700
			);
			expect(fake._pendingSpendSats).to.equal(0);
			expect(stages.map((s) => s.stage)).to.deep.equal([
				'RELEASED',
				'CONFLICTED'
			]);
			expect(
				stages.every(
					(s) => s.id === quote.quoteId && s.compositeId === compositeId
				)
			).to.equal(true);
			expect(stages[0].txid, 'event txid in display order').to.equal(
				reverseHex(TXID_INTERNAL)
			);
			// A second execute of the consumed quote answers the first run.
			const again = await fake.executeChannelSend(quote.quoteId);
			expect(again.compositeId).to.equal(compositeId);
			expect(fake.node.startCalls).to.equal(1);
		});

		it('a composite aborted before release gives its reservation back, and a start refusal does too', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			fake.node.plan = compositePlan();
			const compositeId = '88'.repeat(32);
			fake.node.start = {
				ok: true,
				id: Buffer.from(compositeId, 'hex'),
				plan: compositePlan().plan
			};
			fake.node.records.set(
				compositeId,
				compositeRecord(compositeId, 'PLANNED')
			);
			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			await fake.executeChannelSend(quote.quoteId);
			expect(fake._pendingSpendSats).to.equal(1_200_700);
			fake._onCompositeSpliceStage({
				id: Buffer.from(compositeId, 'hex'),
				stage: 'ABORTED',
				reason: 'peer refused'
			});
			expect(fake._pendingSpendSats, 'released').to.equal(0);
			expect(fake._dailySpentSats, 'nothing charged').to.equal(0);
			expect(fake.getChannelSend(quote.quoteId)!.reason).to.equal(
				'peer refused'
			);

			// A start the engine refuses: the reservation is released at once and
			// the code maps.
			fake.node.start = {
				ok: false,
				error: 'a composite splice is already live',
				code: CompositeSpliceRefusalCode.BUSY
			};
			const second = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			const refused = await refusal(() =>
				fake.executeChannelSend(second.quoteId)
			);
			expect(refused.code).to.equal(BeignetErrorCode.SPLICE_BUSY);
			expect(fake._pendingSpendSats).to.equal(0);
			expect(fake.node.startCalls).to.equal(2);
		});

		it('stages the engine emits inside start() carry the quote id and settle the reservation, and a start that throws releases it', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			fake.node.plan = compositePlan();
			const compositeId = 'a1'.repeat(32);
			const stages: Array<{ id: string; stage: string; compositeId?: string }> =
				[];
			fake.on(
				'channel-send:stage',
				(d: { id: string; stage: string; compositeId?: string }) =>
					stages.push(d)
			);
			// The engine plans, then starts each session; a session that refuses
			// to start aborts the composite before start() has returned ok.
			fake.node.startCompositeSpliceOut = async () => {
				fake.node.startCalls++;
				for (const stage of ['PLANNED', 'NEGOTIATING', 'ABORTED'] as const) {
					const reason =
						stage === 'ABORTED' ? 'session refused to start' : undefined;
					fake.node.records.set(compositeId, {
						...compositeRecord(compositeId, stage),
						...(reason ? { reason } : {})
					});
					fake._onCompositeSpliceStage({
						id: Buffer.from(compositeId, 'hex'),
						stage,
						...(reason ? { reason } : {})
					});
				}
				return {
					ok: true,
					id: Buffer.from(compositeId, 'hex'),
					plan: compositePlan().plan
				};
			};
			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			const run = await fake.executeChannelSend(quote.quoteId);
			expect(run.stage).to.equal('ABORTED');
			expect(run.reason).to.equal('session refused to start');
			expect(run.compositeId).to.equal(compositeId);
			expect(
				fake._pendingSpendSats,
				'released by the abort inside start'
			).to.equal(0);
			expect(fake._dailySpentSats).to.equal(0);
			expect(stages.map((s) => s.stage)).to.deep.equal([
				'PLANNED',
				'NEGOTIATING',
				'ABORTED'
			]);
			expect(
				stages.every(
					(s) => s.id === quote.quoteId && s.compositeId === compositeId
				),
				'relayed under the quote id'
			).to.equal(true);

			// A start that throws: the reservation is released, nothing is
			// registered under the quote, and the quote stays for a retry.
			fake.node.startCompositeSpliceOut = async () => {
				fake.node.startCalls++;
				throw new Error('Node destroyed');
			};
			const second = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			const thrown = await refusal(() =>
				fake.executeChannelSend(second.quoteId)
			);
			expect(thrown.message).to.equal('Node destroyed');
			expect(fake._pendingSpendSats, 'released on the throw').to.equal(0);
			expect(fake.getChannelSend(second.quoteId)).to.equal(null);
			expect(
				fake._channelSendQuotes!.has(second.quoteId),
				'quote kept'
			).to.equal(true);
			expect(fake.node.startCalls).to.equal(2);
		});

		it('a retry while the first execution is still starting awaits it, and two composites starting together never share a reservation', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 5_000_000 });
			fake.node.plan = compositePlan();
			const first = 'b1'.repeat(32);
			let releaseStart: (() => void) | null = null;
			fake.node.startCompositeSpliceOut = () =>
				new Promise((resolve) => {
					fake.node.startCalls++;
					fake.node.records.set(first, compositeRecord(first, 'NEGOTIATING'));
					releaseStart = () =>
						resolve({
							ok: true,
							id: Buffer.from(first, 'hex'),
							plan: compositePlan().plan
						});
				});
			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			const a = fake.executeChannelSend(quote.quoteId);
			const b = fake.executeChannelSend(quote.quoteId);
			await new Promise((r) => setImmediate(r));
			expect(fake.node.startCalls, 'one start for two calls').to.equal(1);
			expect(fake._pendingSpendSats, 'reserved once').to.equal(1_200_700);
			releaseStart!();
			const [ra, rb] = await Promise.all([a, b]);
			expect(ra.compositeId).to.equal(first);
			expect(rb.compositeId).to.equal(first);
			expect(fake.node.startCalls).to.equal(1);
			expect(fake._pendingSpendSats).to.equal(1_200_700);

			// Two quotes executed at once: the second start waits for the first
			// and the engine refuses it BUSY; only the first's reservation stands.
			const other = fakeNode({ channels: twoChannels, limitSats: 5_000_000 });
			other.node.plan = compositePlan();
			const c1 = 'b2'.repeat(32);
			let releaseFirst: (() => void) | null = null;
			other.node.startCompositeSpliceOut = () => {
				other.node.startCalls++;
				if (other.node.startCalls === 1) {
					return new Promise((resolve) => {
						other.node.records.set(c1, compositeRecord(c1, 'NEGOTIATING'));
						releaseFirst = () =>
							resolve({
								ok: true,
								id: Buffer.from(c1, 'hex'),
								plan: compositePlan().plan
							});
					});
				}
				return Promise.resolve({
					ok: false,
					error: 'a composite splice is already live',
					code: CompositeSpliceRefusalCode.BUSY
				});
			};
			const q1 = await other.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000);
			const q2 = await other.quoteChannelSend(REGTEST_ADDRESS, 1_200_000, 1000);
			const e1 = other.executeChannelSend(q1.quoteId);
			const e2 = refusal(() => other.executeChannelSend(q2.quoteId));
			await new Promise((r) => setImmediate(r));
			expect(other.node.startCalls, 'the second waits for the first').to.equal(
				1
			);
			expect(other._pendingSpendSats, 'only the first reserved').to.equal(
				1_200_700
			);
			releaseFirst!();
			const [r1, refused] = await Promise.all([e1, e2]);
			expect(r1.compositeId).to.equal(c1);
			expect(r1.stage).to.equal('NEGOTIATING');
			expect(refused.code).to.equal(BeignetErrorCode.SPLICE_BUSY);
			expect(other.node.startCalls).to.equal(2);
			expect(
				other._pendingSpendSats,
				'the refused start reserved nothing'
			).to.equal(1_200_700);
			expect(other.getChannelSend(q2.quoteId)).to.equal(null);
		});

		it('the fee is priced again at execute: a dearer one is checked against the limits before the engine starts, and the ledger counts it', async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 1_200_800 });
			fake.node.plan = compositePlan();
			const compositeId = 'c1'.repeat(32);
			const quote = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				1_200_000,
				1000
			);
			expect(quote.totalSats).to.equal(1_200_700);
			// A balance moved since the quote: the fee now rounds to 900.
			const dearer = compositePlan();
			(dearer.plan as { feeSats: bigint }).feeSats = 900n;
			fake.node.plan = dearer;
			fake.node.start = {
				ok: true,
				id: Buffer.from(compositeId, 'hex'),
				plan: dearer.plan
			};
			fake.node.records.set(
				compositeId,
				compositeRecord(compositeId, 'NEGOTIATING')
			);
			const over = await refusal(() => fake.executeChannelSend(quote.quoteId));
			expect(over.code).to.equal(BeignetErrorCode.SPENDING_LIMIT_EXCEEDED);
			expect(fake.node.startCalls, 'refused before the engine').to.equal(0);
			expect(fake._pendingSpendSats).to.equal(0);
			// With room in the budget the send runs, and what is reserved and
			// then charged is the fee priced at execute.
			fake._dailySpendLimitSats = 2_000_000;
			const run = await fake.executeChannelSend(quote.quoteId);
			expect(run.feeSats).to.equal(900);
			expect(fake._pendingSpendSats).to.equal(1_200_900);
			fake._onCompositeSpliceStage({
				id: Buffer.from(compositeId, 'hex'),
				stage: 'RELEASED'
			});
			expect(fake._dailySpentSats).to.equal(1_200_900);
			expect(fake._pendingSpendSats).to.equal(0);
		});

		it('a channel the amount cannot leave through is not chosen for a single send: the negotiated dust floor and a fee at or above the amount', async function () {
			const floor = fakeNode({
				channels: [
					{ ...twoChannels[0], dustFloorSats: 10_000 },
					twoChannels[1]
				],
				limitSats: 2_000_000
			});
			const quote = await floor.quoteChannelSend(REGTEST_ADDRESS, 5_000, 1000);
			expect(quote.kind).to.equal('single');
			expect(
				quote.channels[0].channelId,
				'the channel with the lower floor'
			).to.equal(CHANNEL_B);
			const dear = fakeNode({
				channels: [{ ...twoChannels[0], feeSats: 5_000 }, twoChannels[1]],
				limitSats: 2_000_000
			});
			const cheap = await dear.quoteChannelSend(REGTEST_ADDRESS, 5_000, 1000);
			expect(
				cheap.channels[0].channelId,
				'the channel whose fee is below the amount'
			).to.equal(CHANNEL_B);
		});

		it('a malformed or oversized abort reason is refused before the engine is asked', async function () {
			const fake = fakeNode({ channels: twoChannels });
			const compositeId = 'd1'.repeat(32);
			fake.node.records.set(
				compositeId,
				compositeRecord(compositeId, 'NEGOTIATING')
			);
			let abortCalls = 0;
			fake.node.abortCompositeSplice = () => {
				abortCalls++;
				return { ok: true };
			};
			const bad = await refusal(async () =>
				fake.abortChannelSend(compositeId, {
					why: 'object'
				} as unknown as string)
			);
			expect(bad.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
			const long = await refusal(async () =>
				fake.abortChannelSend(compositeId, 'x'.repeat(1025))
			);
			expect(long.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(abortCalls, 'nothing reached the engine').to.equal(0);
			expect(
				fake.abortChannelSend(compositeId, 'operator changed their mind').id
			).to.equal(compositeId);
			expect(abortCalls).to.equal(1);
		});

		it("a single send follows its channel's splice to LOCKED or ABORTED, and sends that ended before the retention window are dropped", async function () {
			const fake = fakeNode({ channels: twoChannels, limitSats: 2_000_000 });
			const stages: Array<{ id: string; stage: string }> = [];
			fake.on('channel-send:stage', (d: { id: string; stage: string }) =>
				stages.push(d)
			);
			const first = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			const runA = await fake.executeChannelSend(first.quoteId);
			expect(runA.channelId).to.equal(CHANNEL_A);
			const txid = reverseHex(TXID_INTERNAL);
			// Another channel's splice is not this send.
			fake._onSingleChannelSendSpliceEvent(CHANNEL_B, 'LOCKED', { txid });
			expect(fake.getChannelSend(first.quoteId)!.stage).to.equal('STARTED');
			fake._onSingleChannelSendSpliceEvent(CHANNEL_A, 'LOCKED', { txid });
			const locked = fake.getChannelSend(first.quoteId)!;
			expect(locked.stage).to.equal('LOCKED');
			expect(locked.txid).to.equal(txid);
			// A later splice on the same channel is not this send either.
			fake._onSingleChannelSendSpliceEvent(CHANNEL_A, 'ABORTED', {
				reason: 'later'
			});
			expect(fake.getChannelSend(first.quoteId)!.stage).to.equal('LOCKED');

			const second = await fake.quoteChannelSend(
				REGTEST_ADDRESS,
				300_000,
				1000
			);
			await fake.executeChannelSend(second.quoteId);
			fake._onSingleChannelSendSpliceEvent(CHANNEL_A, 'ABORTED', {
				reason: 'peer refused'
			});
			const aborted = fake.getChannelSend(second.quoteId)!;
			expect(aborted.stage).to.equal('ABORTED');
			expect(aborted.reason).to.equal('peer refused');
			expect(stages.map((s) => [s.id, s.stage])).to.deep.equal([
				[first.quoteId, 'STARTED'],
				[first.quoteId, 'LOCKED'],
				[second.quoteId, 'STARTED'],
				[second.quoteId, 'ABORTED']
			]);

			// Retention: a send that ended longer ago than the engine keeps its
			// records is dropped from the list; one still under way stays.
			const third = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			await fake.executeChannelSend(third.quoteId);
			const old = Date.now() - COMPOSITE_SPLICE_RETENTION_MS - 60_000;
			fake._channelSends!.get(first.quoteId)!.endedAt = old;
			fake._channelSends!.get(second.quoteId)!.endedAt = old;
			expect(fake.listChannelSends().map((s) => s.id)).to.deep.equal([
				third.quoteId
			]);
			expect(fake.getChannelSend(first.quoteId)).to.equal(null);
			expect(fake.getChannelSend(third.quoteId)!.stage).to.equal('STARTED');
		});

		it('refuses an unknown, malformed or expired quote before any side effect', async function () {
			const fake = fakeNode({ channels: twoChannels });
			expect(
				(await refusal(() => fake.executeChannelSend('zz'))).message
			).to.match(/quoteId/);
			expect(
				(await refusal(() => fake.executeChannelSend('11'.repeat(32)))).code
			).to.equal(BeignetErrorCode.NOT_FOUND);
			const quote = await fake.quoteChannelSend(REGTEST_ADDRESS, 300_000, 1000);
			fake._channelSendQuotes!.get(quote.quoteId)!.quote.expiresAt =
				Date.now() - 1;
			const expired = await refusal(() =>
				fake.executeChannelSend(quote.quoteId)
			);
			expect(expired.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(expired.message).to.match(/expired/);
			expect(fake.node.spliceOutCalls).to.deep.equal([]);
			expect(
				(await refusal(() => fake.executeChannelSend(quote.quoteId))).code
			).to.equal(BeignetErrorCode.NOT_FOUND);
		});

		it('lists restored composites it never quoted, reads them by record id, and routes aborts to the engine', async function () {
			const fake = fakeNode({ channels: twoChannels });
			const compositeId = '66'.repeat(32);
			fake.node.records.set(compositeId, {
				...compositeRecord(compositeId, 'BROADCAST'),
				txid: TXID2_INTERNAL,
				reason: undefined
			});
			const list = fake.listChannelSends();
			expect(list).to.have.length(1);
			expect(list[0].id).to.equal(compositeId);
			expect(list[0].kind).to.equal('composite');
			expect(list[0].stage).to.equal('BROADCAST');
			expect(list[0].amountSats).to.equal(1_200_000);
			expect(list[0].txid, 'display order').to.equal(
				reverseHex(TXID2_INTERNAL)
			);
			expect(fake.getChannelSend(compositeId)!.record!.stage).to.equal(
				'BROADCAST'
			);
			expect(fake.getChannelSend('13'.repeat(32))).to.equal(null);
			// A stage event for a composite nobody quoted is relayed under its own id.
			const seen: Array<{ id: string }> = [];
			fake.on('channel-send:stage', (d: { id: string }) => seen.push(d));
			fake._onCompositeSpliceStage({
				id: Buffer.from(compositeId, 'hex'),
				stage: 'LOCKED'
			});
			expect(seen).to.deep.equal([
				{ id: compositeId, compositeId, stage: 'LOCKED' }
			]);
			expect(fake.abortChannelSend(compositeId).id).to.equal(compositeId);
			fake.node.abortResult = {
				ok: false,
				error: 'composite splice is LOCKED and cannot be aborted',
				code: CompositeSpliceRefusalCode.TOO_LATE
			};
			expect(
				(await refusal(async () => fake.abortChannelSend(compositeId))).code
			).to.equal(BeignetErrorCode.SPLICE_REFUSED);
			fake.node.abortResult = {
				ok: false,
				error: 'composite splice not found',
				code: CompositeSpliceRefusalCode.NOT_FOUND
			};
			expect(
				(await refusal(async () => fake.abortChannelSend('14'.repeat(32)))).code
			).to.equal(BeignetErrorCode.NOT_FOUND);
		});
	});

	describe('daemon routes (offline, no channels)', function () {
		this.timeout(60_000);
		let daemon: IStartedDaemon | null = null;
		let dir = '';
		let port = 0;

		before(async function () {
			dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-channel-send-'));
			daemon = await startDaemon({
				electrumHost: '127.0.0.1',
				electrumPort: 65529,
				electrumTls: false,
				rapidGossipSync: false,
				autoGossipSync: false,
				logLevel: 'silent',
				network: 'regtest',
				mnemonic: MNEMONIC,
				daemonPort: 0,
				dataDir: dir
			});
			port = (daemon.server.address() as AddressInfo).port;
		});

		after(async function () {
			if (daemon) await daemon.stop();
			fs.rmSync(dir, { recursive: true, force: true });
		});

		function request(
			method: 'GET' | 'POST',
			route: string,
			body?: Record<string, unknown>
		): Promise<{ status: number; body: Record<string, unknown> }> {
			return new Promise((resolve, reject) => {
				const payload = body ? JSON.stringify(body) : undefined;
				const req = http.request(
					{
						hostname: '127.0.0.1',
						port,
						path: route,
						method,
						headers: {
							'Content-Type': 'application/json',
							...(payload
								? { 'Content-Length': Buffer.byteLength(payload) }
								: {})
						}
					},
					(res) => {
						let data = '';
						res.on('data', (chunk) => (data += chunk));
						res.on('end', () => {
							try {
								resolve({
									status: res.statusCode ?? 0,
									body: JSON.parse(data)
								});
							} catch (err) {
								reject(err);
							}
						});
					}
				);
				req.on('error', reject);
				if (payload) req.write(payload);
				req.end();
			});
		}

		it('a quote with no channel to pay from is a failure envelope, never a 200', async function () {
			const res = await request('POST', '/channel-send/quote', {
				address: REGTEST_ADDRESS,
				amountSats: 50_000,
				feeratePerkw: 1000
			});
			expect(res.body.ok).to.equal(false);
			expect([409, 503]).to.include(res.status);
			const error = res.body.error as { code: string; message: string };
			expect([
				BeignetErrorCode.SPLICE_REFUSED,
				BeignetErrorCode.NOT_PERSISTED
			]).to.include(error.code);
		});

		it('missing parameters answer 400, an unknown quote 404, an unknown send 404, and the list is empty', async function () {
			let res = await request('POST', '/channel-send/quote', {
				address: REGTEST_ADDRESS
			});
			expect(res.status).to.equal(400);
			res = await request('POST', '/channel-send/execute', {});
			expect(res.status).to.equal(400);
			res = await request('POST', '/channel-send/execute', {
				quoteId: '11'.repeat(32)
			});
			expect(res.status).to.equal(404);
			res = await request('GET', `/channel-send/status?id=${'11'.repeat(32)}`);
			expect(res.status).to.equal(404);
			res = await request('GET', '/channel-send/status');
			expect(res.status).to.equal(400);
			res = await request('GET', '/channel-send/list');
			expect(res.status).to.equal(200);
			expect(res.body.result).to.deep.equal([]);
			res = await request('POST', '/channel-send/abort', {
				id: '11'.repeat(32)
			});
			expect(res.status).to.equal(404);
		});
	});
});

// Keep the type import alive for readers of the fake's shape.
export type { ChannelSendStatus };
