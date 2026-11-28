/**
 * #2151 Step 3b, contract section 8 file 3: two ChannelManagers agree on a
 * conversion layout and stop at the fence after `layout_ack`, in both
 * directions, with the host calls, the frames, the holds and the feerate
 * floor of sections 2 to 4 and amendment v2.1.
 */
import { expect } from 'chai';
import { createHash } from 'crypto';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import {
	encodeUpdateAddHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import { MessageType } from '../../src/lightning/message/types';
import type {
	IAssetConversionContext,
	IAssetConversionTerms
} from '../../src/lightning/channel';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import { finalBranchReaders } from '../../src/lightning/storage/final-branch-readers';
import { plainTypePair, scratch } from './helpers/channel-type-pairs';
import type { IConversionBitcoin } from './helpers/conversion-modules';
import {
	abandoned,
	abortText,
	agreementDigestOf,
	agreeOnTerms,
	allocatedKeyIndex,
	changedRows,
	conversionPair,
	decodeSpliceAck,
	decodeSpliceInit,
	encodeSpliceAck,
	encodeSpliceInit,
	expectFenceHostOrder,
	FENCE,
	frameOf,
	held,
	layoutAckMessage,
	layoutFrames,
	never,
	PAIR_HEIGHT,
	parentBalancesMsat,
	readReply,
	replyMessage,
	roleOf,
	sharedPair,
	startConversion,
	stfu,
	storeTerms,
	stubConversionDescription,
	stubProposal,
	tableRows,
	termsFrames,
	termsIdentity,
	tick,
	track,
	txAbort,
	updateRound,
	type IConversionPair,
	type ITermsOptions,
	type IWireMessage
} from './helpers/conversion-managers';

const PROPOSE = 'Asset conversion host could not propose';
const DESCRIBE = 'Asset conversion host could not describe the layout';
const PREPARE = 'Asset conversion host could not prepare the layout';
const DISAGREE = 'Peers disagree on the asset conversion layout';
const FRAME = 'Invalid asset conversion layout frame';
const PREMATURE = 'Premature asset conversion acknowledgement';
const LAYOUT = 'Invalid asset conversion layout';
const PEER_UPDATED = 'Peer updated the channel during conversion quiescence';
const TIMED_OUT = 'Asset conversion timed out';
const DISCONNECTED = 'Peer disconnected';
const NO_ESTIMATE = 'Asset conversion requires a feerate estimate';
const BELOW_FLOOR = 'Asset conversion funding feerate is below the local floor';
const MARGIN = 'Invalid asset conversion feerate margin';
const ASSET_OPEN_OBJECT_LIMIT = 4 * 1024 * 1024;
const REF = Buffer.alloc(8, 0x3b);
/** A valid key unlike any of the fixtures': the secp256k1 generator. */
const G = Buffer.from(
	'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
	'hex'
);

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
const fakeClock = (): sinon.SinonFakeTimers =>
	sinon.useFakeTimers({
		now: Date.now(),
		toFake: ['Date', 'setTimeout', 'clearTimeout']
	});

/** Side I starts with terms from both stores; returns the tracked start. */
async function run(
	p: IConversionPair,
	I: 0 | 1 = 0,
	options: ITermsOptions = {}
): Promise<ReturnType<typeof track>> {
	agreeOnTerms(p, options);
	const start = track(
		startConversion(p.managers[I], p.channelId, { reference: REF })
	);
	await p.settle();
	await start.done;
	return start;
}

/** Undo what a test changed on a shared pair. */
function clean(p: IConversionPair): void {
	p.link.clearRules();
	p.link.held.splice(0);
	p.hostLog.splice(0);
	agreeOnTerms(p);
	for (const i of [0, 1] as const) {
		const h = p.hosts[i];
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
		h.propose = (): unknown => stubProposal(i);
		h.describe = (ctx, _proposals, bitcoin): unknown =>
			stubConversionDescription(ctx, h.termsFor(ctx), bitcoin);
		h.prepare = (_ctx, _proposals, _bitcoin, layoutDigest): unknown => ({
			digest: sha256(layoutDigest)
		});
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
		margin(p, i, 0);
	}
}

function margin(p: IConversionPair, i: 0 | 1, value: unknown): void {
	(
		p.dualFunding[i] as unknown as { conversionFeerateMarginPerKw: unknown }
	).conversionFeerateMarginPerKw = value;
}

const isLayoutFrame = (m: IWireMessage): boolean =>
	m.name === 'asset_splice:0' || m.name === 'asset_splice:4';
/** The texts of the tx_abort messages side `from` put on the link since `mark`. */
const abortsFrom = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from && m.name === 'TX_ABORT')
		.map(abortText);
const sentNames = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from)
		.map((m) => m.name);
const callsOf = (
	p: IConversionPair,
	side: 0 | 1,
	name: string
): IConversionPair['hostLog'] =>
	p.hostLog.filter((c) => c.side === side && c.name === name);
const addHtlc = (p: IConversionPair, id = 0n): Buffer =>
	encodeUpdateAddHtlcMessage({
		channelId: p.channelId,
		id,
		amountMsat: 1_000_000n,
		paymentHash: sha256(Buffer.alloc(32, 0x45)),
		cltvExpiry: PAIR_HEIGHT + 100,
		onionRoutingPacket: Buffer.alloc(1366)
	});
/** A peer update of the pair's kind, for the observer. */
function peerUpdate(p: IConversionPair): { type: number; payload: Buffer } {
	return p.kind === 'plain'
		? { type: MessageType.UPDATE_ADD_HTLC, payload: addHtlc(p) }
		: {
				type: BEIGNET_CUSTOM_MESSAGE_TYPE,
				payload: encodeCustomMessage(
					BeignetCustomSubtype.ASSET_UPDATE,
					Buffer.concat([p.channelId, Buffer.alloc(8), Buffer.from([1, 0])])
				)
		  };
}
/**
 * A host call that waits: `call` records that it was made and answers only
 * once `release` runs, with what `answer` gives for its arguments.
 */
function holdCall(answer: (...args: unknown[]) => unknown): {
	call: (...args: unknown[]) => Promise<unknown>;
	called: () => boolean;
	release: () => void;
} {
	let open: (() => void) | undefined;
	let was = false;
	return {
		call: (...args: unknown[]): Promise<unknown> => {
			was = true;
			return new Promise((done) => {
				open = (): void => done(answer(...args));
			});
		},
		called: () => was,
		release: () => open?.()
	};
}

describe('Asset conversion to the fence after layout_ack (#2151 step 3b, section 8)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-fence-');
	const pairs = {
		plain: sharedPair(s, 'plain'),
		asset: sharedPair(s, 'asset')
	};
	after(() => s.release());

	for (const kind of ['plain', 'asset'] as const)
		for (const I of [0, 1] as const)
			it(`reaches the fence ${
				kind === 'plain'
					? 'to an asset from a plain parent'
					: 'to bitcoin from an asset parent'
			} with side ${I} initiating`, async () => {
				const p = await pairs[kind]();
				clean(p);
				const A = (1 - I) as 0 | 1;
				const rows = p.stores.map(tableRows);
				const keys = p.stores.map(allocatedKeyIndex);
				const parent = p.stores.map((st) => st.loadFinalChannelType(p.id));
				const info = p.managers.map((m) => m.finalOpeningInfo(p.channelId)[0]);
				const mark = p.link.delivered.length;
				const start = await run(p, I);
				expect(start.error, 'start').to.equal(undefined);

				// Section 3's wire order. The two layout_ack messages may cross.
				const wire = p.link.delivered
					.slice(mark)
					.filter(
						(m) =>
							m.type !== BEIGNET_CUSTOM_MESSAGE_TYPE ||
							m.name.startsWith('conversion_') ||
							isLayoutFrame(m)
					);
				const head = [
					`${I}:conversion_terms`,
					`${A}:conversion_reply`,
					`${I}:STFU`,
					`${A}:STFU`,
					`${I}:SPLICE`,
					`${A}:SPLICE_ACK`,
					`${A}:asset_splice:0`,
					`${I}:asset_splice:0`
				];
				const tail = [`${I}:TX_ABORT`, `${A}:TX_ABORT`];
				const orders = [
					[...head, `${I}:asset_splice:4`, `${A}:asset_splice:4`, ...tail],
					[...head, `${A}:asset_splice:4`, `${I}:asset_splice:4`, ...tail]
				].map((o) => o.join(' '));
				expect(orders).to.include(
					wire.map((m) => m.from + ':' + m.name).join(' ')
				);
				const find = (from: 0 | 1, name: string): IWireMessage =>
					wire.find((m) => m.from === from && m.name === name)!;
				// A sends its layout in the handler that sends its splice_ack.
				expect(find(A, 'asset_splice:0').seq).to.equal(
					find(A, 'SPLICE_ACK').seq + 1
				);

				// The frames name the conversion's own attempt.
				const terms = storeTerms(p.stores[I], p.id, { reference: REF });
				const id = termsIdentity(terms, undefined, roleOf(p.stores[I], p.id));
				for (const m of wire.filter(isLayoutFrame))
					expect(frameOf(m).attempt, m.name).to.deep.equal(id.attempt);
				for (const side of [I, A]) {
					const f = frameOf(find(side, 'asset_splice:0'));
					expect(f.bytes, 'layout of ' + side).to.deep.equal(
						stubProposal(side)
					);
					expect([f.total, f.offset]).to.deep.equal([f.bytes.length, 0]);
					expect(f.digest).to.deep.equal(sha256(f.bytes));
					const ack = frameOf(find(side, 'asset_splice:4'));
					expect([ack.total, ack.offset, ack.bytes.length]).to.deep.equal([
						0, 0, 0
					]);
				}
				expect(abortText(find(I, 'TX_ABORT'))).to.equal(FENCE);
				expect(find(A, 'TX_ABORT').payload).to.deep.equal(
					find(I, 'TX_ABORT').payload
				);

				// The host calls, in section 3's order.
				const calls = p.hostLog.slice(0);
				expectFenceHostOrder(calls, I);
				const call = (
					side: 0 | 1,
					name: string
				): IConversionPair['hostLog'][number] =>
					calls.find((c) => c.side === side && c.name === name)!;
				const init = decodeSpliceInit(find(I, 'SPLICE').payload);
				const ack = decodeSpliceAck(find(A, 'SPLICE_ACK').payload);
				const proposals = [stubProposal(I), stubProposal(A)];
				const opening = (
					side: 0 | 1
				): ReturnType<IConversionPair['stores'][number]['loadFinalOpening']> &
					object => p.stores[side].loadFinalOpening(p.id)!;
				const openerFirst = roleOf(p.stores[I], p.id) === 'opener';
				const order = <T>(v: { opener: T; acceptor: T }): T[] =>
					openerFirst ? [v.opener, v.acceptor] : [v.acceptor, v.opener];
				const fundingTx = Transaction.fromHex(opening(I).fundingTxHex);
				const fundingOut = fundingTx.outs[opening(I).fundingOutputIndex];
				const parentKeys = [I, A].map((side) =>
					Buffer.from(opening(side).localFundingPubkey, 'hex')
				);
				const bitcoins: IConversionBitcoin[] = [];
				for (const side of [I, A]) {
					const propose = call(side, 'proposeConversion');
					expect(propose.args[0], 'propose ctx').to.deep.equal(
						call(side, 'verifyConversionTerms').args[0]
					);
					expect(propose.args[1], 'propose terms').to.deep.equal(
						JSON.parse(id.bytes.toString())
					);
					const describe = call(side, 'describeConversion');
					expect(describe.args[0]).to.deep.equal(propose.args[0]);
					expect(describe.args[1], 'proposals').to.deep.equal(proposals);
					const bitcoin = describe.args[2] as IConversionBitcoin;
					bitcoins.push(bitcoin);
					const root = bitcoin.parent.root;
					if (kind === 'plain')
						expect(root, 'plain parent root').to.equal(undefined);
					else
						expect(
							createTaprootFundingScript(
								parentKeys[0],
								parentKeys[1],
								undefined,
								root
							).p2trOutput,
							'the asset parent root'
						).to.deep.equal(fundingOut.script);
					expect(bitcoin).to.deep.equal({
						fundingKeys: [init.fundingPubkey, ack.fundingPubkey],
						lockTime: init.locktime,
						minimumDepth: terms.lockDepth,
						feeratePerKw: terms.fees.feeratePerKw,
						parent: {
							type: kind,
							channelType: parent[I]!.channelType,
							valueSats: BigInt(fundingOut.value),
							fundingKeys: parentKeys,
							...(root !== undefined && { root })
						},
						candidate: {
							type: kind === 'plain' ? 'asset' : 'plain',
							channelType: terms.targetType,
							maxAcceptedHtlcs: order(terms.candidate.maxAcceptedHtlcs),
							dustLimitSats: order(terms.candidate.dustLimitSats).map(BigInt)
						}
					});
					const prepare = call(side, 'prepareConversion');
					expect(prepare.args.slice(0, 3)).to.deep.equal(describe.args);
				}
				expect(bitcoins[0]).to.deep.equal(bitcoins[1]);
				// Both sides hashed one layout, and the ack is its agreement digest.
				const digests = [I, A].map(
					(side) => call(side, 'prepareConversion').args[3] as Buffer
				);
				expect(digests[0]).to.have.length(32);
				expect(digests[1]).to.deep.equal(digests[0]);
				const agreement = agreementDigestOf(digests[0], sha256(digests[0]));
				for (const side of [I, A])
					expect(frameOf(find(side, 'asset_splice:4')).digest).to.deep.equal(
						agreement
					);
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(abandoned(p, 1)).to.deep.equal([FENCE]);

				// The parent is unchanged. Each side's changed rows are its key
				// allocation's metadata row in its two forms and, since Step 4a, its
				// attempt record and withdrawal in the conversion-attempt scope.
				for (const i of [0, 1] as const) {
					expect(held(p.managers[i], p.id)).to.equal(false);
					expect(p.stores[i].loadFinalChannelType(p.id)).to.deep.equal(
						parent[i]
					);
					const now = p.managers[i].finalOpeningInfo(p.channelId)[0];
					expect(now.localBalanceMsat).to.equal(info[i].localBalanceMsat);
					expect(now.remoteBalanceMsat).to.equal(info[i].remoteBalanceMsat);
					expect(allocatedKeyIndex(p.stores[i])).to.equal(keys[i] + 1);
					const changed = changedRows(rows[i], tableRows(p.stores[i]));
					expect(changed, changed.join('\n')).to.have.length(4);
					expect(
						[
							changed.filter((r) =>
								/^[+-] metadata \{"key":"channel_key_index_allocated"/.test(r)
							).length,
							changed.filter((r) =>
								r.startsWith(
									'+ final_lifecycle_log {"scope":"conversion-attempt","channel_id":"' +
										p.id +
										'"'
								)
							).length
						],
						changed.join('\n')
					).to.deep.equal([2, 2]);
				}
				expect(p.errors).to.deep.equal([[], []]);
				expect(p.unexpected).to.deep.equal([]);
				await updateRound(p);
			});

	for (const [kind, I] of [
		['plain', 0],
		['asset', 1]
	] as const)
		it(`reaches the fence when splice_ack and the layout arrive in one turn (${kind}, M1)`, async () => {
			const p = await pairs[kind]();
			clean(p);
			const A = (1 - I) as 0 | 1;
			p.link.burst(
				(m) =>
					m.from === A &&
					(m.name === 'SPLICE_ACK' || m.name === 'asset_splice:0')
			);
			await run(p, I);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect(abandoned(p, 1)).to.deep.equal([FENCE]);
			expect(p.errors).to.deep.equal([[], []]);
		});
});

describe('Host failures in the layout (#2151 step 3b, section 3)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-host-');
	const shared = sharedPair(s, 'plain');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());

	type Side = 'I' | 'A';
	type Setup = (p: IConversionPair, side: 0 | 1) => void;
	const describeWith =
		(change: (d: Record<string, unknown>) => void): Setup =>
		(p, side) => {
			p.hosts[side].describe = (ctx, _proposals, bitcoin): unknown => {
				const d = stubConversionDescription(
					ctx,
					p.hosts[side].termsFor(ctx),
					bitcoin
				) as unknown as Record<string, unknown>;
				change(d);
				return d;
			};
		};
	const outputs = (
		d: Record<string, unknown>
	): { valueSats: unknown; descriptorHash: Buffer; kind: string }[] =>
		d.outputs as { valueSats: unknown; descriptorHash: Buffer; kind: string }[];
	const cases: [string, Side, Setup, string, boolean?][] = [
		[
			'proposeConversion throws',
			'I',
			(p, i): unknown =>
				(p.hosts[i].propose = (): unknown => {
					throw new Error('no proposal');
				}),
			PROPOSE
		],
		[
			'proposeConversion throws',
			'A',
			(p, i): unknown =>
				(p.hosts[i].propose = (): unknown => {
					throw new Error('no proposal');
				}),
			PROPOSE
		],
		[
			'proposeConversion returns no bytes',
			'I',
			(p, i): unknown => (p.hosts[i].propose = (): unknown => Buffer.alloc(0)),
			PROPOSE
		],
		[
			'proposeConversion returns a string',
			'A',
			(p, i): unknown => (p.hosts[i].propose = (): unknown => 'proposal'),
			PROPOSE
		],
		[
			'proposeConversion returns one byte over the object limit',
			'I',
			(p, i): unknown =>
				(p.hosts[i].propose = (): unknown =>
					Buffer.alloc(ASSET_OPEN_OBJECT_LIMIT + 1, 1)),
			PROPOSE
		],
		[
			'proposeConversion never answers',
			'A',
			(p, i): unknown => (p.hosts[i].propose = (): unknown => never()),
			PROPOSE,
			true
		],
		[
			'describeConversion throws',
			'I',
			(p, i): unknown =>
				(p.hosts[i].describe = (): unknown => {
					throw new Error('no description');
				}),
			DESCRIBE
		],
		[
			'describeConversion never answers',
			'A',
			(p, i): unknown => (p.hosts[i].describe = (): unknown => never()),
			DESCRIBE,
			true
		],
		[
			'a description whose movements are not an array',
			'A',
			describeWith((d) => (d.movements = {})),
			DESCRIBE
		],
		[
			'a description with a number for a bigint',
			'I',
			describeWith(
				(d) => (outputs(d)[0].valueSats = Number(outputs(d)[0].valueSats))
			),
			DESCRIBE
		],
		[
			'a description with a 31 byte descriptor hash',
			'A',
			describeWith((d) => (outputs(d)[0].descriptorHash = Buffer.alloc(31, 1))),
			DESCRIBE
		],
		[
			'a description with a 31 byte txid',
			'I',
			describeWith(
				(d) => ((d.inputs as { txid: Buffer }[])[0].txid = Buffer.alloc(31, 1))
			),
			DESCRIBE
		],
		[
			'a description with a fractional vout',
			'A',
			describeWith((d) => ((d.inputs as { vout: number }[])[0].vout = 0.5)),
			DESCRIBE
		],
		[
			'a description whose isShared is not a boolean',
			'I',
			describeWith(
				(d) => ((d.inputs as { isShared: unknown }[])[0].isShared = 'yes')
			),
			DESCRIBE
		],
		[
			'a description of an output kind outside the union',
			'A',
			describeWith((d) => (outputs(d)[1].kind = 'swap')),
			DESCRIBE
		],
		[
			'a description of a movement from a side outside the union',
			'I',
			describeWith(
				(d) => ((d.movements as { from: string }[])[0].from = 'buyer')
			),
			DESCRIBE
		],
		[
			'a description with three fee budgets',
			'A',
			describeWith((d) => (d.feeBudgets = [...(d.feeBudgets as bigint[]), 0n])),
			DESCRIBE
		],
		[
			'a description with one contribution',
			'I',
			describeWith(
				(d) =>
					(d.relativeSatoshis = (d.relativeSatoshis as bigint[]).slice(0, 1))
			),
			DESCRIBE
		],
		[
			'a description whose record limits are not an array',
			'A',
			describeWith((d) => (d.commitmentRecordLimits = {})),
			DESCRIBE
		],
		[
			"a description whose contribution is one sat off the terms'",
			'I',
			describeWith(
				(d) =>
					(d.relativeSatoshis = [
						(d.relativeSatoshis as bigint[])[0] + 1n,
						(d.relativeSatoshis as bigint[])[1]
					])
			),
			LAYOUT
		],
		[
			"a description whose fee budget is one sat off the terms'",
			'A',
			describeWith(
				(d) =>
					(d.feeBudgets = [
						(d.feeBudgets as bigint[])[0],
						(d.feeBudgets as bigint[])[1] + 1n
					])
			),
			LAYOUT
		],
		[
			'a description that withdraws to an asset',
			'A',
			describeWith((d) => (outputs(d)[1].kind = 'withdrawal')),
			'Unknown asset conversion output role'
		],
		[
			'prepareConversion throws',
			'I',
			(p, i): unknown =>
				(p.hosts[i].prepare = (): unknown => {
					throw new Error('no plan');
				}),
			PREPARE
		],
		[
			'prepareConversion returns a 31 byte digest',
			'A',
			(p, i): unknown =>
				(p.hosts[i].prepare = (): unknown => ({ digest: Buffer.alloc(31, 2) })),
			PREPARE
		],
		[
			'prepareConversion returns nothing',
			'I',
			(p, i): unknown => (p.hosts[i].prepare = (): unknown => undefined),
			PREPARE
		],
		[
			'prepareConversion never answers',
			'A',
			(p, i): unknown => (p.hosts[i].prepare = (): unknown => never()),
			PREPARE,
			true
		]
	];
	for (const [what, side, setup, text, slow] of cases)
		it(`ends both sides when ${side}'s ${what}, with "${text}"`, async () => {
			const p = await shared();
			clean(p);
			const who = side === 'I' ? 0 : 1;
			const keys = p.stores.map(allocatedKeyIndex);
			setup(p, who);
			if (slow) clock = fakeClock();
			const mark = p.link.sent.length;
			await run(p, 0);
			if (slow) {
				expect(abandoned(p, who), 'before the bound').to.deep.equal([]);
				await tick(p, clock!, 15_500);
			}
			expect(abortsFrom(p, who, mark), 'the failing side').to.deep.equal([
				text
			]);
			expect(abortsFrom(p, (1 - who) as 0 | 1, mark), 'the echo').to.deep.equal(
				[text]
			);
			expect(abandoned(p, 0)).to.deep.equal([text]);
			expect(abandoned(p, 1)).to.deep.equal([text]);
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
			expect(p.recycled).to.deep.equal([[], []]);
			// A failed proposal allocates no key; the other side's was allocated before.
			if (text === PROPOSE) {
				expect(allocatedKeyIndex(p.stores[who]), 'no key').to.equal(keys[who]);
				expect(sentNames(p, who, mark)).to.not.include(
					who === 0 ? 'SPLICE' : 'SPLICE_ACK'
				);
				if (who === 1)
					expect(allocatedKeyIndex(p.stores[0])).to.equal(keys[0] + 1);
			}
			expect(
				sentNames(p, who, mark).filter((n) => n === 'asset_splice:4')
			).to.deep.equal([]);
		});

	it('ends both sides with "Peers disagree on the asset conversion layout" when one host describes it differently', async () => {
		const p = await shared();
		clean(p);
		describeWith((d) => {
			for (const o of outputs(d))
				if (o.kind !== 'funding') o.descriptorHash = Buffer.alloc(32, 9);
		})(p, 1);
		const mark = p.link.sent.length;
		await run(p, 0);
		expect(abandoned(p, 0)).to.deep.equal([DISAGREE]);
		expect(abandoned(p, 1)).to.deep.equal([DISAGREE]);
		const aborts = [...abortsFrom(p, 0, mark), ...abortsFrom(p, 1, mark)];
		expect(aborts.length).to.be.at.least(2);
		expect(
			aborts.every((t) => t === DISAGREE),
			aborts.join(', ')
		).to.equal(true);
		expect(p.recycled).to.deep.equal([[], []]);
		const prepared = [0, 1].map(
			(i) => callsOf(p, i as 0 | 1, 'prepareConversion')[0].args[3] as Buffer
		);
		expect(prepared[0]).to.not.deep.equal(prepared[1]);
	});

	it("takes the peer's tx_abort at once while its own describe waits past the host bound (S4)", async () => {
		const p = await shared();
		clean(p);
		clock = fakeClock();
		p.hosts[1].describe = (): unknown => never();
		p.hosts[0].prepare = (): unknown => {
			throw new Error('no plan');
		};
		const mark = p.link.sent.length;
		await run(p, 0);
		expect(abortsFrom(p, 0, mark)).to.deep.equal([PREPARE]);
		expect(
			abortsFrom(p, 1, mark),
			'the echo, before the held describe answers'
		).to.deep.equal([PREPARE]);
		expect(abandoned(p, 0)).to.deep.equal([PREPARE]);
		expect(abandoned(p, 1)).to.deep.equal([PREPARE]);
		await tick(p, clock, 20_000);
		expect(p.recycled).to.deep.equal([[], []]);
		expect(abortsFrom(p, 0, mark)).to.deep.equal([PREPARE]);
		expect(abortsFrom(p, 1, mark)).to.deep.equal([PREPARE]);
	});
});

describe('The observer while a layout step waits (#2151 step 3b, M2 and v2.1 item 5)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-observer-');
	after(() => s.release());

	for (const [kind, side] of [
		['plain', 'I'],
		['asset', 'A']
	] as const)
		it(`sends one tx_abort when the peer updates while ${side}'s describeConversion waits, and nothing when it answers (${kind})`, async () => {
			const p = await conversionPair(s, kind);
			const who = side === 'I' ? 0 : 1;
			const peer = (1 - who) as 0 | 1;
			const h = p.hosts[who];
			const gate = holdCall((ctx, _proposals, bitcoin) =>
				stubConversionDescription(
					ctx as IAssetConversionContext,
					h.termsFor(ctx as IAssetConversionContext),
					bitcoin as IConversionBitcoin
				)
			);
			h.describe = gate.call;
			const mark = p.link.sent.length;
			await run(p, 0);
			expect(gate.called(), 'describe called').to.equal(true);
			const update = peerUpdate(p);
			p.link.inject(peer, update.type, update.payload);
			await p.settle();
			expect(abortsFrom(p, who, mark)).to.deep.equal([PEER_UPDATED]);
			gate.release();
			await p.settle();
			expect(abortsFrom(p, who, mark)).to.deep.equal([PEER_UPDATED]);
			expect(abortsFrom(p, peer, mark), 'the echo').to.deep.equal([
				PEER_UPDATED
			]);
			expect(sentNames(p, who, mark)).to.not.include('asset_splice:4');
			expect(abandoned(p, 0)).to.deep.equal([PEER_UPDATED]);
			expect(abandoned(p, 1)).to.deep.equal([PEER_UPDATED]);
			expect(callsOf(p, who, 'prepareConversion')).to.deep.equal([]);
			// No splice transport took a conversion message.
			expect(
				p.link.sent
					.slice(mark)
					.filter((m) => m.name === 'TX_ABORT')
					.map(abortText)
			).to.not.include('Refused splice negotiation');
			expect([
				held(p.managers[0], p.id),
				held(p.managers[1], p.id)
			]).to.deep.equal([false, false]);
		});

	it("sends one tx_abort when the peer updates after its stfu(0) while I's proposeConversion waits, allocating no key (v2.1 item 5)", async () => {
		const p = await conversionPair(s, 'plain');
		const gate = holdCall(() => stubProposal(0));
		p.hosts[0].propose = gate.call;
		const keys = allocatedKeyIndex(p.stores[0]);
		const mark = p.link.sent.length;
		await run(p, 0);
		expect(gate.called(), 'propose called').to.equal(true);
		p.link.inject(1, MessageType.UPDATE_ADD_HTLC, addHtlc(p));
		await p.settle();
		gate.release();
		await p.settle();
		expect(abortsFrom(p, 0, mark)).to.deep.equal([PEER_UPDATED]);
		expect(sentNames(p, 0, mark)).to.not.include('SPLICE');
		expect(allocatedKeyIndex(p.stores[0])).to.equal(keys);
		expect(abandoned(p, 0)).to.deep.equal([PEER_UPDATED]);
		expect(abandoned(p, 1)).to.deep.equal([PEER_UPDATED]);
		expect(held(p.managers[0], p.id)).to.equal(false);
	});

	it('meets the observer, not the quiescence check, with an update in the same burst as the peer stfu(0) (v2.1 item 8)', async () => {
		const p = await conversionPair(s, 'plain');
		agreeOnTerms(p);
		p.link.script(1);
		const start = track(
			startConversion(p.managers[0], p.channelId, { reference: REF })
		);
		await p.settle();
		await start.done;
		const t = storeTerms(p.stores[0], p.id, { reference: REF });
		const id = termsIdentity(t);
		p.link.send(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest)
		);
		await p.settle();
		expect(p.link.inbox[1].some((m) => m.name === 'STFU')).to.equal(true);
		// stfu(0) and an add with no turn between them.
		p.managers[0].handleMessage(
			p.nodeIds[1],
			MessageType.STFU,
			stfu(p.channelId, false)
		);
		p.managers[0].handleMessage(
			p.nodeIds[1],
			MessageType.UPDATE_ADD_HTLC,
			addHtlc(p)
		);
		await p.settle();
		expect(
			p.link.inbox[1].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([PEER_UPDATED]);
		expect(p.link.inbox[1].some((m) => m.name === 'SPLICE')).to.equal(false);
	});
});

describe('An attempt in laid-out (#2151 step 3b, section 3)', function () {
	this.timeout(90000);
	const s = scratch('conversion-laid-out-');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());
	const ackOfA = { from: 1 as const, name: 'asset_splice:4' };
	const layoutOfI = { from: 0 as const, name: 'asset_splice:0' };

	it('ends both sides at a disconnect and replays nothing after the reconnect', async () => {
		const p = await conversionPair(s, 'asset');
		p.link.hold(ackOfA);
		await run(p, 0);
		expect(p.link.held.map((m) => m.name)).to.deep.equal(['asset_splice:4']);
		expect(abandoned(p, 0)).to.deep.equal([]);
		p.link.held.splice(0);
		p.disconnect();
		expect(abandoned(p, 0)).to.deep.equal([DISCONNECTED]);
		expect(abandoned(p, 1)).to.deep.equal([DISCONNECTED]);
		p.link.clearRules();
		const mark = p.link.sent.length;
		await p.reconnect();
		expect(
			p.link.sent
				.slice(mark)
				.filter(
					(m) =>
						m.name.startsWith('conversion_') ||
						m.name.startsWith('asset_splice') ||
						['STFU', 'SPLICE', 'SPLICE_ACK', 'TX_ABORT'].includes(m.name)
				)
				.map((m) => m.name)
		).to.deep.equal([]);
		await updateRound(p);
	});

	for (const [side, hold] of [
		['I', ackOfA],
		['A', layoutOfI]
	] as const)
		it(`aborts on a peer update while ${side} is laid-out, then delivers it`, async () => {
			const p = await conversionPair(s, 'plain');
			const who = side === 'I' ? 0 : 1;
			p.link.hold(hold);
			const mark = p.link.sent.length;
			await run(p, 0);
			expect(abandoned(p, who)).to.deep.equal([]);
			p.link.inject(
				(1 - who) as 0 | 1,
				MessageType.UPDATE_ADD_HTLC,
				addHtlc(p)
			);
			await p.settle();
			expect(abortsFrom(p, who, mark)).to.deep.equal([PEER_UPDATED]);
			expect(abandoned(p, 0)).to.deep.equal([PEER_UPDATED]);
			expect(abandoned(p, 1)).to.deep.equal([PEER_UPDATED]);
			expect(p.managers[who].finalUpdateStatus(p.id)?.pending).to.deep.include({
				direction: 'peer',
				type: MessageType.UPDATE_ADD_HTLC
			});
		});

	it('times out at the deadline in laid-out', async () => {
		const p = await conversionPair(s, 'plain');
		clock = fakeClock();
		p.link.hold(ackOfA);
		await run(p, 0);
		await tick(p, clock, 59_000);
		expect(abandoned(p, 0)).to.deep.equal([]);
		await tick(p, clock, 1_500);
		expect(abortsFrom(p, 0)).to.deep.equal([TIMED_OUT]);
		expect(abandoned(p, 0)).to.deep.equal([TIMED_OUT]);
		expect(abandoned(p, 1)).to.deep.equal([TIMED_OUT]);
	});
});

describe('Received layout frames (#2151 step 3b, section 3 and v2.1 item 13)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-frames-');
	after(() => s.release());

	/** Real I (side 0), scripted A (side 1), up to I's splice_init. */
	async function toInitSent(p: IConversionPair): Promise<{
		t: IAssetConversionTerms;
		id: ReturnType<typeof termsIdentity>;
		ack: Buffer;
	}> {
		expect(p.opener).to.equal(0);
		agreeOnTerms(p);
		p.link.script(1);
		const start = track(
			startConversion(p.managers[0], p.channelId, { reference: REF })
		);
		await p.settle();
		await start.done;
		const t = storeTerms(p.stores[0], p.id, { reference: REF });
		const id = termsIdentity(t);
		p.link.send(
			1,
			BEIGNET_CUSTOM_MESSAGE_TYPE,
			replyMessage(id.attempt, id.digest)
		);
		await p.settle();
		p.link.send(1, MessageType.STFU, stfu(p.channelId, false));
		await p.settle();
		const init = p.link.inbox[1].find((m) => m.name === 'SPLICE');
		expect(init, "I's splice_init").to.not.equal(undefined);
		const ack = encodeSpliceAck({
			channelId: p.channelId,
			relativeSatoshis: BigInt(t.contributions.acceptor),
			fundingPubkey: G,
			lockDepth: t.lockDepth,
			conversion: {
				termsDigest: id.digest,
				targetType: Buffer.from(t.targetType, 'hex')
			}
		});
		return { t, id, ack };
	}
	const sendAll = (p: IConversionPair, from: 0 | 1, raws: Buffer[]): void => {
		for (const raw of raws) p.link.send(from, BEIGNET_CUSTOM_MESSAGE_TYPE, raw);
	};
	/** I's tx_abort texts, then the scripted echo and I's end. */
	async function endsI(p: IConversionPair, text: string): Promise<void> {
		const aborts = p.link.inbox[1].filter((m) => m.name === 'TX_ABORT');
		expect(aborts.map(abortText)).to.deep.equal([text]);
		p.link.send(1, MessageType.TX_ABORT, aborts[0].payload);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([text]);
		expect(held(p.managers[0], p.id)).to.equal(false);
	}
	const big = Buffer.alloc(40 * 1024, 0x61);

	const refusals: [
		string,
		(p: IConversionPair, attempt: Buffer, ack: Buffer) => Buffer[],
		string
	][] = [
		[
			'a second, different layout object',
			(_p, attempt): Buffer[] => [
				...layoutFrames(attempt, Buffer.from('first layout')),
				...layoutFrames(attempt, Buffer.from('second layout'))
			],
			FRAME
		],
		[
			'a layout object over the object limit',
			(_p, attempt): Buffer[] => [
				assetSpliceFrame(
					attempt,
					Buffer.alloc(32 * 1024, 1),
					ASSET_OPEN_OBJECT_LIMIT + 1
				)
			],
			FRAME
		],
		[
			'a chunk that differs on replay',
			(_p, attempt): Buffer[] => {
				const frames = layoutFrames(attempt, big);
				const changed = Buffer.from(big);
				changed[5] ^= 1;
				return [frames[0], layoutFrames(attempt, changed, sha256(big))[0]];
			},
			FRAME
		],
		[
			'a layout chunk whose digest does not match the object',
			(_p, attempt): Buffer[] =>
				layoutFrames(attempt, Buffer.from('layout'), Buffer.alloc(32, 7)),
			FRAME
		],
		[
			'an acknowledgement frame carrying bytes',
			(_p, attempt): Buffer[] => [
				...layoutFrames(attempt, Buffer.from('layout')),
				layoutAckMessage(attempt, Buffer.alloc(32, 3), Buffer.from([1]))
			],
			FRAME
		]
	];
	for (const [what, frames, text] of refusals)
		it(`fails the initiator on ${what} with "${text}"`, async () => {
			const p = await conversionPair(s, 'plain');
			const { id, ack } = await toInitSent(p);
			p.link.send(1, MessageType.SPLICE_ACK, ack);
			await p.settle();
			expect(
				p.link.inbox[1].filter((m) => m.name === 'asset_splice:0').length,
				"I's layout"
			).to.equal(1);
			sendAll(p, 1, frames(p, id.attempt, ack));
			await p.settle();
			await endsI(p, text);
		});

	it(`fails the initiator on a layout_ack before its own layout was sent with "${PREMATURE}"`, async () => {
		const p = await conversionPair(s, 'plain');
		const { id } = await toInitSent(p);
		sendAll(p, 1, [layoutAckMessage(id.attempt, Buffer.alloc(32, 4))]);
		await p.settle();
		await endsI(p, PREMATURE);
		expect(p.link.inbox[1].some((m) => m.name === 'asset_splice:0')).to.equal(
			false
		);
	});

	it('ignores a whole identical replay of a complete layout, and reaches the fence', async () => {
		const p = await conversionPair(s, 'plain');
		const { id, ack } = await toInitSent(p);
		p.link.send(1, MessageType.SPLICE_ACK, ack);
		const layout = Buffer.from('scripted acceptor layout');
		sendAll(p, 1, [
			...layoutFrames(id.attempt, layout),
			...layoutFrames(id.attempt, layout)
		]);
		await p.settle();
		const own = p.link.inbox[1].filter((m) => m.name === 'asset_splice:4');
		expect(own, "I's layout_ack").to.have.length(1);
		const describe = callsOf(p, 0, 'describeConversion');
		expect(describe).to.have.length(1);
		expect(describe[0].args[1]).to.deep.equal([stubProposal(0), layout]);
		const L = callsOf(p, 0, 'prepareConversion')[0].args[3] as Buffer;
		expect(frameOf(own[0]).digest).to.deep.equal(
			agreementDigestOf(L, sha256(L))
		);
		sendAll(p, 1, [layoutAckMessage(id.attempt, frameOf(own[0]).digest)]);
		await p.settle();
		await endsI(p, FENCE);
	});

	it("keeps a layout that arrives before the peer's splice_ack, and runs the layout steps on the ack (M1)", async () => {
		const p = await conversionPair(s, 'plain');
		const { id, ack } = await toInitSent(p);
		const layout = Buffer.from('scripted acceptor layout, sent early');
		sendAll(p, 1, layoutFrames(id.attempt, layout));
		await p.settle();
		expect(
			callsOf(p, 0, 'describeConversion'),
			'no steps in init-sent'
		).to.deep.equal([]);
		expect(p.link.inbox[1].some((m) => m.name === 'TX_ABORT')).to.equal(false);
		p.link.send(1, MessageType.SPLICE_ACK, ack);
		await p.settle();
		expect(
			p.link.inbox[1].map((m) => m.name).slice(-2),
			"I's layout, then its layout_ack"
		).to.deep.equal(['asset_splice:0', 'asset_splice:4']);
		const describe = callsOf(p, 0, 'describeConversion');
		expect(describe).to.have.length(1);
		expect(describe[0].args[1]).to.deep.equal([stubProposal(0), layout]);
		const own = p.link.inbox[1].filter((m) => m.name === 'asset_splice:4');
		const L = callsOf(p, 0, 'prepareConversion')[0].args[3] as Buffer;
		expect(frameOf(own[0]).digest).to.deep.equal(
			agreementDigestOf(L, sha256(L))
		);
		sendAll(p, 1, [layoutAckMessage(id.attempt, frameOf(own[0]).digest)]);
		await p.settle();
		await endsI(p, FENCE);
	});

	/** Scripted I (side 0), real A (side 1), up to A's layout_ack. */
	async function toAcceptorAck(
		p: IConversionPair
	): Promise<{ id: ReturnType<typeof termsIdentity>; digest: Buffer }> {
		expect(p.opener).to.equal(0);
		agreeOnTerms(p);
		p.link.script(0);
		const t = storeTerms(p.stores[0], p.id);
		const id = termsIdentity(t);
		sendAll(p, 0, termsFrames(id.attempt, id.bytes));
		await p.settle();
		p.link.send(0, MessageType.STFU, stfu(p.channelId, true));
		await p.settle();
		p.link.send(
			0,
			MessageType.SPLICE,
			encodeSpliceInit({
				channelId: p.channelId,
				relativeSatoshis: BigInt(t.contributions.opener),
				fundingFeeratePerkw: t.fees.feeratePerKw,
				locktime: PAIR_HEIGHT,
				fundingPubkey: G,
				lockDepth: t.lockDepth,
				conversion: {
					termsDigest: id.digest,
					targetType: Buffer.from(t.targetType, 'hex')
				}
			})
		);
		await p.settle();
		const names = p.link.inbox[0].map((m) => m.name);
		expect(names.slice(-2), "A's splice_ack and layout").to.deep.equal([
			'SPLICE_ACK',
			'asset_splice:0'
		]);
		sendAll(
			p,
			0,
			layoutFrames(id.attempt, Buffer.from('scripted initiator layout'))
		);
		await p.settle();
		const own = p.link.inbox[0].filter((m) => m.name === 'asset_splice:4');
		expect(own, "A's layout_ack").to.have.length(1);
		const L = callsOf(p, 1, 'prepareConversion')[0].args[3] as Buffer;
		const digest = frameOf(own[0]).digest;
		expect(digest).to.deep.equal(agreementDigestOf(L, sha256(L)));
		return { id, digest };
	}

	it(`fails the acceptor on a second layout_ack that differs with "${DISAGREE}"`, async () => {
		const p = await conversionPair(s, 'plain');
		const { id, digest } = await toAcceptorAck(p);
		const other = Buffer.from(digest);
		other[0] ^= 1;
		sendAll(p, 0, [
			layoutAckMessage(id.attempt, digest),
			layoutAckMessage(id.attempt, other)
		]);
		await p.settle();
		expect(
			p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([DISAGREE]);
		p.link.send(0, MessageType.TX_ABORT, txAbort(p.channelId, DISAGREE));
		await p.settle();
		expect(abandoned(p, 1)).to.deep.equal([DISAGREE]);
	});

	it(`fails the acceptor on a layout_ack that differs with "${DISAGREE}"`, async () => {
		const p = await conversionPair(s, 'plain');
		const { id, digest } = await toAcceptorAck(p);
		const other = Buffer.from(digest);
		other[31] ^= 1;
		sendAll(p, 0, [layoutAckMessage(id.attempt, other)]);
		await p.settle();
		expect(
			p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([DISAGREE]);
	});

	it('ignores an identical second layout_ack at the acceptor, which ends at the fence', async () => {
		const p = await conversionPair(s, 'plain');
		const { id, digest } = await toAcceptorAck(p);
		sendAll(p, 0, [
			layoutAckMessage(id.attempt, digest),
			layoutAckMessage(id.attempt, digest)
		]);
		await p.settle();
		expect(p.link.inbox[0].some((m) => m.name === 'TX_ABORT')).to.equal(false);
		expect(held(p.managers[1], p.id)).to.equal(true);
		p.link.send(0, MessageType.TX_ABORT, txAbort(p.channelId, FENCE));
		await p.settle();
		expect(
			p.link.inbox[0].filter((m) => m.name === 'TX_ABORT').map(abortText)
		).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		expect(held(p.managers[1], p.id)).to.equal(false);
	});
});

/** A raw layout frame with a total of the test's choosing. */
function assetSpliceFrame(
	attempt: Buffer,
	bytes: Buffer,
	total: number
): Buffer {
	const head = Buffer.alloc(74);
	head[0] = 1;
	head[1] = 0;
	attempt.copy(head, 2);
	sha256(bytes).copy(head, 34);
	head.writeUInt32BE(total, 66);
	head.writeUInt32BE(0, 70);
	return encodeCustomMessage(
		BeignetCustomSubtype.ASSET_SPLICE,
		Buffer.concat([head, bytes])
	);
}

describe('The feerate floor (#2151 step 3b, section 4 check 9)', function () {
	this.timeout(90000);
	const s = scratch('conversion-floor-');
	const shared = sharedPair(s, 'plain');
	let clock: sinon.SinonFakeTimers | undefined;
	afterEach(() => {
		clock?.restore();
		clock = undefined;
	});
	after(() => s.release());
	const estimate =
		(v: unknown): (() => Promise<number>) =>
		async () =>
			v as number;
	const replyTo0 = (
		p: IConversionPair,
		mark: number
	): ReturnType<typeof readReply>[] =>
		p.link.delivered
			.slice(mark)
			.filter((m) => m.from === 1 && m.name === 'conversion_reply')
			.map(readReply);

	it("refuses the initiator's own start when its floor is above the terms' feerate", async () => {
		const p = await shared();
		clean(p);
		p.feerateEstimates[0] = estimate(1001);
		const mark = p.link.sent.length;
		const start = await run(p, 0);
		expect(start.error).to.equal(BELOW_FLOOR);
		expect(sentNames(p, 0, mark)).to.deep.equal([]);
		expect(p.hostLog.map((c) => c.side + ':' + c.name)).to.deep.equal([
			'0:conversionTerms'
		]);
		expect(held(p.managers[0], p.id)).to.equal(false);
	});

	it("declines at the acceptor in its reply when its floor is above the terms' feerate", async () => {
		const p = await shared();
		clean(p);
		p.feerateEstimates[1] = estimate(1001);
		const mark = p.link.delivered.length;
		await run(p, 0);
		expect(replyTo0(p, mark).map((r) => [r.accept, r.reason])).to.deep.equal([
			[false, BELOW_FLOOR]
		]);
		expect(abandoned(p, 0)).to.deep.equal([BELOW_FLOOR]);
		expect(p.hosts[1].calls()).to.deep.equal([]);
	});

	it('lets two estimates meet through the margin', async () => {
		const p = await shared();
		clean(p);
		p.feerateEstimates[1] = estimate(1400);
		margin(p, 1, 399);
		await run(p, 0);
		expect(abandoned(p, 0)).to.deep.equal([BELOW_FLOOR]);
		clean(p);
		p.feerateEstimates[1] = estimate(1400);
		margin(p, 1, 400);
		await run(p, 0);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('keeps the floor at MIN_FEERATE_PER_KW however large the margin', async () => {
		const p = await shared();
		clean(p);
		for (const i of [0, 1] as const) {
			p.feerateEstimates[i] = estimate(300);
			margin(p, i, 100);
		}
		const low = await run(p, 0, { feeratePerKw: 252 });
		expect(low.error).to.equal(BELOW_FLOOR);
		p.hostLog.splice(0);
		const ok = await run(p, 0, { feeratePerKw: 253 });
		expect(ok.error).to.equal(undefined);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
	});

	for (const [what, answer] of [
		['undefined', estimate(undefined)],
		['null', estimate(null)],
		['0', estimate(0)],
		['a negative value', estimate(-5)],
		['NaN', estimate(NaN)],
		['Infinity', estimate(Infinity)],
		[
			'a throw',
			async (): Promise<number> => {
				throw new Error('no estimate');
			}
		]
	] as const)
		it(`refuses the initiator's start on an estimate of ${what}`, async () => {
			const p = await shared();
			clean(p);
			p.feerateEstimates[0] = answer;
			const start = await run(p, 0);
			expect(start.error).to.equal(NO_ESTIMATE);
			expect(p.hostLog.map((c) => c.side + ':' + c.name)).to.deep.equal([
				'0:conversionTerms'
			]);
		});

	it("refuses the initiator's start when the estimate never answers within the host bound", async () => {
		const p = await shared();
		clean(p);
		clock = fakeClock();
		p.feerateEstimates[0] = (): Promise<number> => never();
		agreeOnTerms(p);
		const start = track(
			startConversion(p.managers[0], p.channelId, { reference: REF })
		);
		await p.settle();
		expect(start.settled).to.equal(false);
		await tick(p, clock, 15_500);
		await start.done;
		expect(start.error).to.equal(NO_ESTIMATE);
	});

	it('declines at the acceptor with no estimate', async () => {
		const p = await shared();
		clean(p);
		p.feerateEstimates[1] = estimate(undefined);
		const mark = p.link.delivered.length;
		await run(p, 0);
		expect(replyTo0(p, mark).map((r) => r.reason)).to.deep.equal([NO_ESTIMATE]);
		expect(abandoned(p, 0)).to.deep.equal([NO_ESTIMATE]);
	});

	it('refuses a start on a manager configured with no estimate', async () => {
		const p = await conversionPair(s, 'plain', {
			conversionFeerateEstimate: [null, undefined]
		});
		const start = await run(p, 0);
		expect(start.error).to.equal(NO_ESTIMATE);
	});

	for (const [who, hold] of [
		['I', { from: 1, name: 'STFU' }],
		['A', { from: 0, name: 'SPLICE' }]
	] as const)
		it(`runs the floor again at ${who}'s proposal point, before any proposal or key`, async () => {
			const p = await shared();
			clean(p);
			const side = who === 'I' ? 0 : 1;
			p.link.hold(hold);
			const keys = allocatedKeyIndex(p.stores[side]);
			const mark = p.link.sent.length;
			await run(p, 0);
			p.feerateEstimates[side] = estimate(1001);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(abortsFrom(p, side, mark)).to.deep.equal([BELOW_FLOOR]);
			expect(callsOf(p, side, 'proposeConversion')).to.deep.equal([]);
			expect(allocatedKeyIndex(p.stores[side])).to.equal(keys);
			expect(sentNames(p, side, mark)).to.not.include(
				side === 0 ? 'SPLICE' : 'SPLICE_ACK'
			);
			expect(abandoned(p, 0)).to.deep.equal([BELOW_FLOOR]);
			expect(abandoned(p, 1)).to.deep.equal([BELOW_FLOOR]);
		});

	for (const bad of [-1, 0.5, 100_001, '0'] as const) {
		it(`refuses the initiator's start when its live margin is ${JSON.stringify(
			bad
		)}`, async () => {
			const p = await shared();
			clean(p);
			margin(p, 0, bad);
			const start = await run(p, 0);
			expect(start.error).to.equal(MARGIN);
			margin(p, 0, 0);
		});
		it(`declines at the acceptor when its live margin is ${JSON.stringify(
			bad
		)}`, async () => {
			const p = await shared();
			clean(p);
			margin(p, 1, bad);
			const mark = p.link.delivered.length;
			await run(p, 0);
			expect(replyTo0(p, mark).map((r) => r.reason)).to.deep.equal([MARGIN]);
			margin(p, 1, 0);
		});
	}
});

describe('Routing of the layout frames (#2151 step 3b, section 2)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-routing-');
	after(() => s.release());

	interface ISeen {
		subtype: number;
		raw: Buffer;
	}
	function spy(p: IConversionPair): [ISeen[], ISeen[]] {
		const seen: [ISeen[], ISeen[]] = [[], []];
		for (const i of [0, 1] as const) {
			const t = (
				p.managers[i] as unknown as {
					assetSplice?: {
						custom(peer: string, subtype: number, raw: Buffer): void;
					};
				}
			).assetSplice;
			expect(t, 'the asset splice transport').to.not.equal(undefined);
			const original = t!.custom.bind(t);
			t!.custom = (peer, subtype, raw): void => {
				seen[i].push({ subtype, raw: Buffer.from(raw) });
				original(peer, subtype, raw);
			};
		}
		return seen;
	}
	const names = (seen: ISeen[], attempt: Buffer): ISeen[] =>
		seen.filter((x) => x.raw.includes(attempt));

	it('gives the conversion its own frames, and the asset splice transport every other', async () => {
		const p = await conversionPair(s, 'asset');
		const seen = spy(p);
		agreeOnTerms(p);
		const terms = storeTerms(p.stores[0], p.id, { reference: REF });
		const { attempt } = termsIdentity(
			terms,
			undefined,
			roleOf(p.stores[0], p.id)
		);
		// Hold A's layout_ack: I is laid-out when the other frames arrive.
		p.link.hold({ from: 1, name: 'asset_splice:4' });
		await run(p, 0);
		expect(names(seen[0], attempt), 'I').to.deep.equal([]);
		expect(names(seen[1], attempt), 'A').to.deep.equal([]);
		// A consent frame (subtype 99) naming the attempt, and a layout of another attempt.
		const consent = encodeCustomMessage(
			BeignetCustomSubtype.ASSET_SPLICE_CONSENT,
			Buffer.concat([
				Buffer.from([1]),
				attempt,
				Buffer.alloc(32, 5),
				Buffer.alloc(64, 6)
			])
		);
		const stranger = layoutFrames(
			Buffer.alloc(32, 0x77),
			Buffer.from('another attempt')
		)[0];
		for (const raw of [consent, stranger]) {
			const { subtype, payload } = decodeCustomMessage(raw);
			p.managers[0].handleAssetOpenFrame(p.nodeIds[1], subtype, payload);
		}
		expect(seen[0].map((x) => x.subtype)).to.deep.equal([
			BeignetCustomSubtype.ASSET_SPLICE_CONSENT,
			BeignetCustomSubtype.ASSET_SPLICE
		]);
		expect(abandoned(p, 0)).to.deep.equal([]);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		// After the end, a frame naming the attempt routes as today.
		const late = layoutFrames(attempt, Buffer.from('late layout'))[0];
		const { subtype, payload } = decodeCustomMessage(late);
		p.managers[1].handleAssetOpenFrame(p.nodeIds[0], subtype, payload);
		await p.settle();
		expect(names(seen[1], attempt).map((x) => x.raw[1])).to.deep.equal([0]);
		expect(p.link.sent.filter((m) => m.name === 'TX_ABORT').length).to.equal(2);
		await updateRound(p);
	});
});

describe('Copies of what the host is given and gives back (#2151 step 3b, v2.4 items 2 and 4)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-copies-');
	const shared = sharedPair(s, 'plain');
	after(() => s.release());

	/** Side 0 starts; `prepare` runs after agreeOnTerms, before the start. */
	async function startWith(
		p: IConversionPair,
		prepare: () => void
	): Promise<ReturnType<typeof track>> {
		agreeOnTerms(p);
		prepare();
		const start = track(
			startConversion(p.managers[0], p.channelId, { reference: REF })
		);
		await p.settle();
		await start.done;
		return start;
	}
	type Ctx = Omit<IAssetConversionContext, 'attempt'> & { attempt?: Buffer };
	const LATER = [
		'verifyConversionTerms',
		'proposeConversion',
		'describeConversion',
		'prepareConversion',
		'abandonConversion'
	];

	it("passes later host calls the engine's own context when the host changes the one conversionTerms got (v2.4 item 4)", async () => {
		const p = await shared();
		clean(p);
		let given: unknown;
		const start = await startWith(p, () => {
			const terms = p.hosts[0].terms;
			p.hosts[0].terms = (ctx, request): ReturnType<typeof terms> => {
				given = JSON.parse(JSON.stringify(ctx));
				const c = ctx as unknown as Record<string, unknown> & {
					parent: Record<string, unknown>;
				};
				c.channelId = 'ee'.repeat(32);
				c.peer = '02' + 'ee'.repeat(32);
				c.isOpener = !c.isOpener;
				c.direction = c.direction === 'to-asset' ? 'to-plain' : 'to-asset';
				c.parent.txid = 'ee'.repeat(32);
				c.parent.outputIndex = 7;
				c.parent.stateNumber = '999';
				return terms(ctx, request);
			};
		});
		expect(start.error, 'start').to.equal(undefined);
		const later = p.hostLog.filter(
			(c) => c.side === 0 && c.name !== 'conversionTerms'
		);
		for (const c of later) {
			const { attempt, ...rest } = c.args[0] as Ctx;
			expect(attempt, c.name).to.not.equal(undefined);
			expect(JSON.parse(JSON.stringify(rest)), c.name).to.deep.equal(given);
		}
		expect(later.map((c) => c.name)).to.deep.equal(LATER);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('passes later host calls and the wire the attempt id when each host overwrites the bytes verifyConversionTerms got (v2.4 item 4)', async () => {
		const p = await shared();
		clean(p);
		const terms = storeTerms(p.stores[0], p.id, { reference: REF });
		const { attempt } = termsIdentity(
			terms,
			undefined,
			roleOf(p.stores[0], p.id)
		);
		const mark = p.link.sent.length;
		await startWith(p, () => {
			for (const i of [0, 1] as const)
				p.hosts[i].verify = (ctx): unknown => {
					ctx.attempt.fill(0xee);
					return true;
				};
		});
		for (const i of [0, 1] as const) {
			const later = p.hostLog.filter(
				(c) => c.side === i && LATER.slice(1).includes(c.name)
			);
			expect(later.map((c) => c.name)).to.deep.equal(LATER.slice(1));
			for (const c of later)
				expect((c.args[0] as Ctx).attempt, i + ':' + c.name).to.deep.equal(
					attempt
				);
		}
		const frames = p.link.sent
			.slice(mark)
			.filter((m) => m.type === BEIGNET_CUSTOM_MESSAGE_TYPE);
		expect(frames.map((m) => m.name)).to.include.members([
			'conversion_terms',
			'conversion_reply',
			'asset_splice:0',
			'asset_splice:4'
		]);
		for (const m of frames)
			expect(frameOf(m).attempt, m.from + ':' + m.name).to.deep.equal(attempt);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('copies the description once: a descriptorHash getter that answers 2 bytes on its second read leaves both layouts equal (v2.4 item 2)', async () => {
		const p = await shared();
		clean(p);
		const h = p.hosts[1];
		h.describe = (ctx, _proposals, bitcoin): unknown => {
			const d = stubConversionDescription(
				ctx,
				h.termsFor(ctx),
				bitcoin
			) as unknown as { outputs: Record<string, unknown>[] };
			const o = d.outputs[d.outputs.length - 1];
			const good = o.descriptorHash as Buffer;
			let reads = 0;
			Object.defineProperty(o, 'descriptorHash', {
				enumerable: true,
				get: (): Buffer => (reads++ === 0 ? good : good.subarray(0, 2))
			});
			return d;
		};
		await run(p, 0);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('ends both sides with the describe text, not a TypeError, when a host describes a sparse outputs array (v2.4 item 2)', async () => {
		const p = await shared();
		clean(p);
		const h = p.hosts[1];
		h.describe = (ctx, _proposals, bitcoin): unknown => {
			const d = stubConversionDescription(
				ctx,
				h.termsFor(ctx),
				bitcoin
			) as unknown as { outputs: unknown[] };
			d.outputs = [...d.outputs];
			d.outputs.length += 1;
			return d;
		};
		const mark = p.link.sent.length;
		await run(p, 0);
		expect(abortsFrom(p, 1, mark)).to.deep.equal([DESCRIBE]);
		expect(abortsFrom(p, 0, mark), 'the echo').to.deep.equal([DESCRIBE]);
		expect(abandoned(p, 0)).to.deep.equal([DESCRIBE]);
		expect(abandoned(p, 1)).to.deep.equal([DESCRIBE]);
	});
});

describe('The estimate as a method of the config (#2151 step 3b, v2.4 item 5)', function () {
	this.timeout(90000);
	const s = scratch('conversion-estimate-method-');
	after(() => s.release());

	it("calls config.conversionFeerateEstimate as the config's method, so one that reads this is the floor's estimate", async () => {
		const rates = { perKw: 1000 };
		const config = {
			rates,
			conversionFeerateEstimate(this: {
				rates: { perKw: number };
			}): Promise<number> {
				return Promise.resolve(this.rates.perKw);
			}
		};
		const p = await conversionPair(s, 'plain', {
			conversionFeerateEstimate: [null, null],
			config: [config, config]
		});
		const start = await run(p, 0);
		expect(start.error, 'start').to.equal(undefined);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		// The method's own answer is the estimate: above the terms' feerate, the start is refused.
		clean(p);
		rates.perKw = 1001;
		const refused = await run(p, 0);
		expect(refused.error).to.equal(BELOW_FLOOR);
	});
});

describe('Frame order and late host answers (#2151 step 3b, sections 2 and 3)', function () {
	this.timeout(90000);
	const s = scratch('conversion-layout-order-');
	const shared = sharedPair(s, 'plain');
	after(() => s.release());

	it('routes a frame naming the attempt from another peer to the asset splice transport (section 2, ownsFrame)', async () => {
		const p = await shared();
		clean(p);
		const seen: { peer: string; raw: Buffer }[] = [];
		const t = (
			p.managers[0] as unknown as {
				assetSplice: {
					custom(peer: string, subtype: number, raw: Buffer): void;
				};
			}
		).assetSplice;
		const original = t.custom;
		t.custom = (peer, subtype, raw): void => {
			seen.push({ peer, raw: Buffer.from(raw) });
			original.call(t, peer, subtype, raw);
		};
		try {
			const terms = storeTerms(p.stores[0], p.id, { reference: REF });
			const { attempt } = termsIdentity(
				terms,
				undefined,
				roleOf(p.stores[0], p.id)
			);
			// I is laid-out with its agreement when the stranger's frame arrives.
			p.link.hold({ from: 1, name: 'asset_splice:4' });
			await run(p, 0);
			expect(callsOf(p, 0, 'prepareConversion')).to.have.length(1);
			const stranger = '02' + '5a'.repeat(32);
			for (const raw of [
				layoutAckMessage(attempt, Buffer.alloc(32, 0x5a)),
				layoutFrames(attempt, Buffer.from('a stranger layout'))[0]
			]) {
				const { subtype, payload } = decodeCustomMessage(raw);
				p.managers[0].handleAssetOpenFrame(stranger, subtype, payload);
			}
			await p.settle();
			expect(
				seen.filter((x) => x.raw.includes(attempt)).map((x) => x.peer)
			).to.deep.equal([stranger, stranger]);
			expect(abandoned(p, 0)).to.deep.equal([]);
			p.link.clearRules();
			p.link.release();
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		} finally {
			t.custom = original;
		}
	});

	it("reaches the fence when A's layout_ack reaches I before A's layout: I compares once its own agreement is in", async () => {
		const p = await shared();
		clean(p);
		p.link.hold({ from: 1, name: 'asset_splice:0' });
		const mark = p.link.sent.length;
		const seen = p.link.delivered.length;
		await run(p, 0);
		expect(
			p.link.delivered
				.slice(seen)
				.filter((m) => m.from === 1 && isLayoutFrame(m))
				.map((m) => m.name),
			"A's layout_ack, ahead of its held layout"
		).to.deep.equal(['asset_splice:4']);
		expect(callsOf(p, 0, 'describeConversion')).to.deep.equal([]);
		expect(abandoned(p, 0)).to.deep.equal([]);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abortsFrom(p, 0, mark)).to.deep.equal([FENCE]);
		expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		expect(abandoned(p, 1)).to.deep.equal([FENCE]);
	});

	it('sends no layout_ack from I when a peer tx_abort ends it while its prepareConversion waits (the await rule)', async () => {
		const p = await shared();
		clean(p);
		const h = p.hosts[0];
		const gate = holdCall((_ctx, _proposals, _bitcoin, layoutDigest) => ({
			digest: sha256(layoutDigest as Buffer)
		}));
		h.prepare = gate.call;
		p.hosts[1].prepare = (): unknown => {
			throw new Error('no plan');
		};
		p.link.hold({ from: 1, name: 'TX_ABORT' });
		const mark = p.link.sent.length;
		await run(p, 0);
		expect(gate.called(), "I's prepare called").to.equal(true);
		p.link.clearRules();
		p.link.release();
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal([PREPARE]);
		expect(abortsFrom(p, 0, mark), 'the echo').to.deep.equal([PREPARE]);
		gate.release();
		await p.settle();
		expect(sentNames(p, 0, mark)).to.not.include('asset_splice:4');
		expect(abortsFrom(p, 0, mark)).to.deep.equal([PREPARE]);
		expect(p.recycled).to.deep.equal([[], []]);
	});

	it('sends no layout_ack from A when a disconnect ends it while its prepareConversion waits (the await rule)', async () => {
		const p = await conversionPair(s, 'asset');
		const h = p.hosts[1];
		const gate = holdCall((_ctx, _proposals, _bitcoin, layoutDigest) => ({
			digest: sha256(layoutDigest as Buffer)
		}));
		h.prepare = gate.call;
		await run(p, 0);
		expect(gate.called(), "A's prepare called").to.equal(true);
		p.disconnect();
		expect(abandoned(p, 1)).to.deep.equal([DISCONNECTED]);
		const mark = p.link.sent.length;
		gate.release();
		await p.settle();
		expect(sentNames(p, 1, mark)).to.deep.equal([]);
	});
});

describe('The parent reader (#2151 step 3b, section 5)', function () {
	this.timeout(90000);
	const s = scratch('conversion-parent-reader-');
	after(() => s.release());
	const UNREADY = 'Asset conversion requires a funded ready channel';
	const reader = (
		store: IConversionPair['stores'][number],
		id: string
	): ReturnType<
		NonNullable<ReturnType<typeof finalBranchReaders>>['assetConversionParent']
	> => finalBranchReaders(store)!.assetConversionParent(id);
	const opening = (
		store: IConversionPair['stores'][number],
		id: string
	): [bigint, bigint] => {
		const o = store.loadFinalOpening(id)!;
		return [
			BigInt(o.localContributionSats) * 1000n,
			BigInt(o.remoteContributionSats) * 1000n
		];
	};
	const PAYMENT_MSAT = 7_000_000n;
	const preimage = Buffer.alloc(32, 0x52);

	it("reads a plain parent's balances from its locked ledger state after a payment", () => {
		const t = plainTypePair(s);
		const { id, stores } = t;
		const roots = t.sides.map((side) => side.root);
		const channelId = Buffer.from(id, 'hex');
		const exchange = (from: number): void => {
			const sig = stores[from].signFinalUpdateCommitment(id, roots[from]);
			const ack = stores[1 - from].acceptFinalUpdateCommitment(
				id,
				roots[1 - from],
				sig
			);
			stores[from].acceptFinalUpdateRevocation(id, ack);
		};
		const stage = (from: number, type: number, wire: Buffer): void => {
			stores[from].stageFinalHtlcUpdate(id, 'local', type, wire);
			stores[1 - from].stageFinalHtlcUpdate(id, 'peer', type, wire);
			exchange(from);
			exchange(1 - from);
		};
		const before = stores.map((st) => opening(st, id));
		expect(stores.map((st) => reader(st, id).localBalanceMsat)).to.deep.equal(
			before.map((b) => b[0])
		);
		// Side 0 pays side 1: an add, then its fulfill.
		stage(
			0,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId,
				id: 0n,
				amountMsat: PAYMENT_MSAT,
				paymentHash: sha256(preimage),
				cltvExpiry: PAIR_HEIGHT + 100,
				onionRoutingPacket: Buffer.alloc(1366)
			})
		);
		stage(
			1,
			MessageType.UPDATE_FULFILL_HTLC,
			encodeUpdateFulfillHtlcMessage({
				channelId,
				id: 0n,
				paymentPreimage: preimage
			})
		);
		for (const store of stores)
			for (const event of store.loadFinalUpdateDeliveries(id))
				store.ackFinalUpdateDelivery(id, event.id);
		for (const i of [0, 1] as const) {
			const r = reader(stores[i], id);
			const delta = i === 0 ? -PAYMENT_MSAT : PAYMENT_MSAT;
			expect(
				[r.localBalanceMsat, r.remoteBalanceMsat],
				'side ' + i
			).to.deep.equal([before[i][0] + delta, before[i][1] - delta]);
			const view = parentBalancesMsat(stores[i], id);
			expect([r.localBalanceMsat, r.remoteBalanceMsat]).to.deep.equal([
				view.local,
				view.remote
			]);
			expect(r.root).to.equal(undefined);
			expect(r.priorDigest).to.equal(undefined);
		}
	});

	it("reads an asset parent's balances from the committed round's member on the live funding, and the round's digest", async () => {
		const p = await conversionPair(s, 'asset');
		const before = p.stores.map((st) => opening(st, p.id));
		for (const i of [0, 1] as const) {
			const r = reader(p.stores[i], p.id);
			expect(
				[r.localBalanceMsat, r.remoteBalanceMsat],
				'at N = 0'
			).to.deep.equal(before[i]);
			expect(r.priorDigest, 'at N = 0').to.equal(undefined);
		}
		await p.managers[0].startAssetSpliceUpdate(p.channelId, [
			{
				kind: 'add',
				htlc: {
					id: 0n,
					offeredBy: 'local',
					amountMsat: PAYMENT_MSAT,
					paymentHash: sha256(preimage),
					cltvExpiry: PAIR_HEIGHT + 100,
					allocations: []
				}
			}
		]);
		await p.settle();
		await p.managers[1].startAssetSpliceUpdate(p.channelId, [
			{ kind: 'fulfill', offeredBy: 'peer', id: 0n, preimage }
		]);
		await p.settle();
		expect(p.errors).to.deep.equal([[], []]);
		for (const i of [0, 1] as const) {
			const store = p.stores[i];
			const head = store.assetSpliceUpdateHead(p.id) as unknown as {
				committed?: { digest: string; height: string | number | bigint };
			};
			expect(String(head.committed?.height), 'N').to.equal('2');
			const r = reader(store, p.id);
			const delta = i === 0 ? -PAYMENT_MSAT : PAYMENT_MSAT;
			expect(
				[r.localBalanceMsat, r.remoteBalanceMsat],
				'side ' + i
			).to.deep.equal([before[i][0] + delta, before[i][1] - delta]);
			const member = parentBalancesMsat(store, p.id);
			expect([r.localBalanceMsat, r.remoteBalanceMsat]).to.deep.equal([
				member.local,
				member.remote
			]);
			expect(r.priorDigest).to.equal(head.committed!.digest);
			expect(r.root).to.equal(
				store.loadFinalOpeningSession(p.id)!.assetEvidence!.fundingRoot
			);
		}
		// No member of the committed round is the live funding under the root the
		// reader takes (an adopted receipt naming another root): it fails closed.
		const store = p.stores[0] as unknown as {
			loadAdoptedAssetSpliceReceipt(id: string): unknown;
		};
		const original = store.loadAdoptedAssetSpliceReceipt;
		store.loadAdoptedAssetSpliceReceipt = (): unknown => ({
			candidate: { fundingRoot: 'ff'.repeat(32) }
		});
		try {
			expect(() => reader(p.stores[0], p.id)).to.throw(UNREADY);
		} finally {
			store.loadAdoptedAssetSpliceReceipt = original;
		}
		expect(reader(p.stores[0], p.id).localBalanceMsat).to.equal(
			before[0][0] - PAYMENT_MSAT
		);
	});
});
