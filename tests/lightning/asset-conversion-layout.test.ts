/**
 * #2151 Step 3b, contract section 8 file 2: the engine's pure layout checks
 * (section 4) and the layout digest.
 *
 * Each case starts from a sample layout that passes, changes it by the
 * smallest step that breaks one check (one sat, one unit or one serial
 * bit), and pins the text from both sides of the same layout. Cases on the
 * channel roles run again with the channel's acceptor initiating. The
 * layout digest is computed in the test from the contract's formula.
 *
 * The agreement digest has no function of its own in the contract, so it is
 * pinned on the wire by asset-conversion-layout-flow.test.ts.
 */
import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import { auxiliaryCarrierError } from '../../src/lightning/channel/auxiliary-funding';
import { funderCommitmentCostSats } from '../../src/lightning/channel/commitment-builder';
import {
	finalFunderCostMsat,
	finalFundingReserveSats
} from '../../src/lightning/channel/final-commitment-reserve';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { assetSpliceCommitmentBytes } from '../../src/lightning/features/asset-splice';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { MAX_MONEY_SATS } from '../../src/lightning/interactive-tx/validation';
import {
	decodeSpliceAck,
	decodeSpliceInit,
	encodeSpliceAck,
	encodeSpliceInit,
	PLAIN_TARGET_TYPE_HEX
} from './helpers/conversion-managers';
import {
	conversionLayout,
	type IConversionLayout,
	type IConversionLayoutBase,
	type IConversionLayoutExpectation
} from './helpers/conversion-modules';
import {
	ASSET_A,
	ASSET_B,
	buildSample,
	layoutDigestOf,
	sampleCoin,
	sampleParent,
	SAMPLE_KEYS,
	SAMPLE_ROOT,
	sha256,
	specOf,
	type ILayoutSpec,
	type ISample
} from './helpers/conversion-layout-sample';

type Direction = 'to-asset' | 'to-plain';
const BOTH: readonly Direction[] = ['to-asset', 'to-plain'];
const TO_ASSET: readonly Direction[] = ['to-asset'];
const TO_PLAIN: readonly Direction[] = ['to-plain'];

const T = {
	layout: 'Invalid asset conversion layout',
	keys: 'Invalid asset conversion parent or funding keys',
	count: 'Invalid asset conversion item count',
	serial: 'Invalid asset conversion serial order or reuse',
	shared: 'Incorrect shared asset conversion input',
	external: 'Invalid external asset conversion input',
	mismatch: 'External asset conversion transaction mismatch',
	input: 'Invalid asset conversion input',
	amount: 'Invalid asset conversion output amount',
	funding: 'Incorrect asset conversion funding output',
	role: 'Unknown asset conversion output role',
	fees: 'Asset conversion exceeds its fee budgets',
	first: 'Asset conversion first commitment does not add up',
	units: 'Asset conversion units differ from its terms',
	credit: 'Asset conversion credits an output its owner did not add',
	reserve: 'Splice breaches the channel reserve or commitment fee budget'
} as const;

/**
 * The verdict of checkConversionLayout: the text of its throw, or a text it
 * returns, or undefined when the layout passes. A missing module rethrows.
 */
function verdict(
	layout: IConversionLayout,
	expectation: IConversionLayoutExpectation
): string | undefined {
	const check = conversionLayout().checkConversionLayout;
	let out: unknown;
	try {
		out = check(layout, expectation);
	} catch (error) {
		return error instanceof Error ? error.message : String(error);
	}
	return typeof out === 'string' ? out : undefined;
}

/** Both sides' verdicts on the sample's layout. */
const verdicts = (s: ISample): (string | undefined)[] =>
	s.expectations.map((x) => verdict(s.layout, x));

const flip = (b: Buffer, index = b.length - 1): Buffer => {
	const c = Buffer.from(b);
	c[index] ^= 1;
	return c;
};
/** The same point with the other parity: equal by x-only. */
const negated = (key: Buffer): Buffer => {
	const c = Buffer.from(key);
	c[0] = c[0] === 2 ? 3 : 2;
	return c;
};
type SpliceInit = ReturnType<typeof decodeSpliceInit>;
type SpliceAck = ReturnType<typeof decodeSpliceAck>;
const reinit = (
	l: IConversionLayout,
	change: (m: SpliceInit) => void
): void => {
	const m = decodeSpliceInit(l.init);
	change(m);
	l.init = encodeSpliceInit(m);
};
const reack = (l: IConversionLayout, change: (m: SpliceAck) => void): void => {
	const m = decodeSpliceAck(l.ack);
	change(m);
	l.ack = encodeSpliceAck(m);
};
const outputOf = (
	l: IConversionLayout,
	s: ISample,
	key: string
): IConversionLayout['outputs'][number] =>
	l.outputs.find((o) => o.serialId === s.serialOf(key))!;
const inputOf = (
	l: IConversionLayout,
	s: ISample,
	key: string
): IConversionLayout['inputs'][number] =>
	l.inputs.find((i) => i.serialId === s.serialOf(key))!;
/** The last output that is not the funding output. */
const lastOwnOutput = (
	l: IConversionLayout
): IConversionLayout['outputs'][number] =>
	[...l.outputs].reverse().find((o) => o.role !== 'funding')!;
const movementOf = (
	l: IConversionLayout,
	s: ISample,
	assetId: string,
	output: string,
	index = 0
): IConversionLayout['movements'][number] =>
	l.movements.filter(
		(m) => m.assetId === assetId && m.outputSerial === s.serialOf(output)
	)[index];

interface ICase {
	what: string;
	in: readonly Direction[];
	/** Change the spec before the sample is built (terms and layout agree). */
	spec?: (s: ILayoutSpec) => void;
	/** Change the built layout only. */
	layout?: (l: IConversionLayout, s: ISample) => void;
	/** Change both sides' expectations. */
	expectation?: (x: IConversionLayoutExpectation) => void;
	/** The text from both sides, or undefined when the layout passes. */
	text: string | undefined | ((s: ISample) => string);
	/** Also run with the channel's acceptor initiating. */
	roles?: boolean;
}

function sampleFor(
	c: ICase,
	direction: Direction,
	openerInitiates: boolean
): ISample {
	const spec = specOf(direction);
	spec.openerInitiates = openerInitiates;
	c.spec?.(spec);
	const s = buildSample(spec);
	c.layout?.(s.layout, s);
	if (c.expectation) s.expectations.forEach(c.expectation);
	return s;
}

function runCases(check: string, cases: ICase[]): void {
	for (const c of cases)
		for (const direction of c.in)
			for (const openerInitiates of c.roles ? [true, false] : [true]) {
				const who = openerInitiates ? '' : ', the channel acceptor initiating';
				const outcome = c.text === undefined ? 'passes' : 'fails';
				it(`${check}: ${outcome} with ${c.what} (${direction}${who})`, () => {
					const s = sampleFor(c, direction, openerInitiates);
					const text = typeof c.text === 'function' ? c.text(s) : c.text;
					expect(verdicts(s)).to.deep.equal([text, text]);
				});
			}
}

/** The spec's coin and change amounts for a seller fee of `fee` (to an asset). */
const sellerChange = (s: ILayoutSpec, coin: bigint, fee: bigint): void => {
	s.inputs.find((i) => i.key === 'coin')!.value = coin;
	s.outputs.find((o) => o.key === 'change')!.amount = coin - fee;
};
/** Make the opener the seller to an asset: its coin and change, its budget. */
const openerSells = (s: ILayoutSpec): void => {
	s.holder = 'opener';
	s.fundingPayer = 'opener';
	s.budgets = { opener: 1500n, acceptor: 0n };
	for (const i of s.inputs)
		if (i.owner === 'acceptor') (i.owner = 'opener'), (i.serial = 4n);
	for (const o of s.outputs)
		if (o.owner === 'acceptor') (o.owner = 'opener'), (o.serial = 6n);
	for (const m of s.movements) m.from = 'opener';
	s.firstUnits = [
		{ assetId: ASSET_A, opener: 1000n, acceptor: 0n },
		{ assetId: ASSET_B, opener: 500n, acceptor: 0n }
	];
};
/** Balances of both the parent and the first commitment, opener first, msat. */
const balances = (
	s: ILayoutSpec,
	parentOpener: bigint,
	firstOpener: bigint
): void => {
	const capacity =
		s.parentValue + s.contributions.opener + s.contributions.acceptor;
	s.parentBalances = {
		opener: parentOpener,
		acceptor: s.parentValue * 1000n - parentOpener
	};
	s.firstBalances = {
		opener: firstOpener,
		acceptor: capacity * 1000n - firstOpener
	};
};
const policy = (s: ILayoutSpec): Parameters<typeof finalFunderCostMsat>[0] => ({
	localDustLimitSatoshis: Number(s.dust.opener),
	remoteDustLimitSatoshis: Number(s.dust.acceptor),
	commitmentFeeratePerKw: s.commitmentFeeratePerKw
});
/** The opener's commitment fee and anchors, msat, as check 12 prices them. */
const costMsat = (s: ILayoutSpec): bigint => finalFunderCostMsat(policy(s), []);
const OVERLAY = ((): Buffer => {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_TAPROOT_OVERLAY);
	return flags.toBuffer();
})();
/** The cost check 13 names, sats. */
const carrierCostSats = (s: ILayoutSpec): bigint =>
	funderCommitmentCostSats(s.commitmentFeeratePerKw, 0, OVERLAY);

describe('Asset conversion layout checks (#2151 step 3b, section 4)', function () {
	for (const direction of BOTH)
		for (const openerInitiates of [true, false])
			it(`accepts the sample ${direction} layout from both sides${
				openerInitiates ? '' : ', the channel acceptor initiating'
			}`, () => {
				const spec = specOf(direction);
				spec.openerInitiates = openerInitiates;
				expect(verdicts(buildSample(spec))).to.deep.equal([
					undefined,
					undefined
				]);
			});

	describe('check 1, the negotiation and the terms', () => {
		const odd = Buffer.from('fe0001000701ff', 'hex');
		runCases('check 1', [
			{
				what: 'an init that does not re-encode byte for byte',
				in: BOTH,
				layout: (l): unknown => (l.init = Buffer.concat([l.init, odd])),
				text: T.layout
			},
			{
				what: 'an ack that does not re-encode byte for byte',
				in: BOTH,
				layout: (l): unknown => (l.ack = Buffer.concat([l.ack, odd])),
				text: T.layout
			},
			{
				what: 'an init without the conversion TLV',
				in: BOTH,
				layout: (l): unknown => reinit(l, (m) => delete m.conversion),
				text: T.layout
			},
			{
				what: 'an ack whose conversion TLV names a digest one bit off',
				in: BOTH,
				layout: (l): unknown =>
					reack(
						l,
						(m) =>
							(m.conversion = {
								...m.conversion!,
								termsDigest: flip(m.conversion!.termsDigest)
							})
					),
				text: T.layout
			},
			{
				what: 'an init whose conversion TLV names another target type',
				in: BOTH,
				layout: (l): unknown =>
					reinit(
						l,
						(m) =>
							(m.conversion = {
								...m.conversion!,
								targetType: flip(m.conversion!.targetType, 0)
							})
					),
				text: T.layout
			},
			{
				what: 'a chain hash one bit off regtest',
				in: BOTH,
				layout: (l): unknown => (l.chainHash = flip(l.chainHash)),
				text: T.layout
			},
			{
				what: 'an init naming a channel one bit off',
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.channelId = flip(m.channelId))),
				text: T.layout
			},
			{
				what: 'an ack naming a channel one bit off',
				in: BOTH,
				layout: (l): unknown =>
					reack(l, (m) => (m.channelId = flip(m.channelId))),
				text: T.layout
			},
			{
				what: "a layout channel id one bit off the init's and ack's",
				in: BOTH,
				layout: (l): unknown => (l.channelId = flip(l.channelId)),
				text: T.layout
			},
			{
				what: 'an init requiring confirmed inputs',
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.requireConfirmedInputs = true)),
				text: T.layout
			},
			{
				what: 'an ack requiring confirmed inputs',
				in: BOTH,
				layout: (l): unknown =>
					reack(l, (m) => (m.requireConfirmedInputs = true)),
				text: T.layout
			},
			{
				what: "an init lock depth one above the terms'",
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.lockDepth = (m.lockDepth ?? 0) + 1)),
				text: T.layout
			},
			{
				what: "an ack lock depth one above the terms'",
				in: BOTH,
				layout: (l): unknown =>
					reack(l, (m) => (m.lockDepth = (m.lockDepth ?? 0) + 1)),
				text: T.layout
			},
			{
				what: "an init funding feerate one above the terms'",
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.fundingFeeratePerkw = m.fundingFeeratePerkw + 1)),
				text: T.layout
			},
			{
				what: 'an init contribution one sat above the expected',
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.relativeSatoshis = m.relativeSatoshis + 1n)),
				text: T.layout
			},
			{
				what: 'an ack contribution one sat below the expected',
				in: BOTH,
				layout: (l): unknown =>
					reack(l, (m) => (m.relativeSatoshis = m.relativeSatoshis - 1n)),
				text: T.layout
			},
			{
				what: "an expected contribution one sat off the init's",
				in: BOTH,
				expectation: (x): unknown =>
					(x.relativeSatoshis = [
						x.relativeSatoshis[0] + 1n,
						x.relativeSatoshis[1]
					]),
				text: T.layout
			},
			{
				what: 'three parent keys',
				in: BOTH,
				layout: (l): unknown =>
					(l.parentKeys = [
						...l.parentKeys,
						getPublicKey(sha256('third parent key'))
					] as unknown as IConversionLayout['parentKeys']),
				text: T.layout
			},
			{
				what: 'one parent key',
				in: BOTH,
				layout: (l): unknown =>
					(l.parentKeys = [
						l.parentKeys[0]
					] as unknown as IConversionLayout['parentKeys']),
				text: T.layout
			},
			{
				what: "a state number one above the terms'",
				in: BOTH,
				layout: (l): unknown => (l.stateNumber = l.stateNumber + 1n),
				text: T.layout
			},
			{
				what: "a parent output index other than the terms'",
				in: BOTH,
				layout: (l): unknown => (l.parentIndex = 0),
				text: T.layout
			},
			{
				what: "a parent transaction other than the terms' (same funding output)",
				in: BOTH,
				layout: (l): unknown =>
					(l.parent = sampleParent(
						BigInt(l.parent.outs[l.parentIndex].value),
						l.parentKeys,
						l.parentRoot,
						'another parent'
					)),
				text: T.layout
			},
			{
				what: 'a terms digest one bit off',
				in: BOTH,
				layout: (l): unknown => (l.termsDigest = flip(l.termsDigest)),
				text: T.layout
			},
			{
				what: 'a target type one bit off',
				in: BOTH,
				layout: (l): unknown => (l.targetType = flip(l.targetType, 0)),
				text: T.layout
			},
			{
				what: 'the other direction',
				in: BOTH,
				layout: (l): unknown =>
					(l.direction = l.direction === 'to-asset' ? 'to-plain' : 'to-asset'),
				text: T.layout
			},
			{
				what: "a layout funding feerate one above the terms'",
				in: BOTH,
				layout: (l): unknown => (l.feeratePerKw = l.feeratePerKw + 1),
				text: T.layout
			},
			{
				what: "an initiator HTLC limit one below the terms'",
				in: BOTH,
				layout: (l): unknown =>
					(l.candidateMaxAcceptedHtlcs = [
						l.candidateMaxAcceptedHtlcs[0] - 1,
						l.candidateMaxAcceptedHtlcs[1]
					]),
				text: T.layout
			},
			{
				what: "an acceptor dust limit one sat above the terms'",
				in: BOTH,
				layout: (l): unknown =>
					(l.candidateDustSats = [
						l.candidateDustSats[0],
						l.candidateDustSats[1] + 1n
					]),
				text: T.layout
			},
			{
				what: "a first commitment balance one msat off the terms'",
				in: BOTH,
				layout: (l): unknown =>
					(l.firstCommitment = {
						...l.firstCommitment,
						balanceMsat: [
							l.firstCommitment.balanceMsat[0] + 1n,
							l.firstCommitment.balanceMsat[1] - 1n
						]
					}),
				text: T.layout
			},
			{
				what: "first commitment units one unit off the terms'",
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.firstCommitment = {
						...l.firstCommitment,
						units: l.firstCommitment.units.map((u, i) =>
							i === 0
								? {
										...u,
										initiator: u.initiator + 1n,
										acceptor: u.acceptor - 1n
								  }
								: u
						)
					}),
				text: T.layout
			},
			{
				what: "a fee budget one sat above the terms'",
				in: BOTH,
				layout: (l): unknown =>
					(l.feeBudgets = [l.feeBudgets[0] + 1n, l.feeBudgets[1]]),
				text: T.layout
			}
		]);
	});

	describe('check 2, the parent and the funding keys', () => {
		runCases('check 2', [
			{
				what: 'an invalid init funding key',
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.fundingPubkey = Buffer.alloc(33, 5))),
				text: T.keys
			},
			{
				what: "an ack funding key equal to the init's by x-only",
				in: BOTH,
				layout: (l): unknown =>
					reack(l, (m) => (m.fundingPubkey = negated(SAMPLE_KEYS[2]))),
				text: T.keys
			},
			{
				what: 'a candidate key equal to a parent key by x-only',
				in: BOTH,
				layout: (l): unknown =>
					reinit(l, (m) => (m.fundingPubkey = negated(SAMPLE_KEYS[0]))),
				text: T.keys
			},
			{
				what: 'an invalid parent key',
				in: BOTH,
				layout: (l): unknown =>
					(l.parentKeys = [Buffer.alloc(33, 5), l.parentKeys[1]]),
				text: T.keys
			},
			{
				what: 'a parent key the funding script does not use',
				in: BOTH,
				layout: (l): unknown =>
					(l.parentKeys = [
						l.parentKeys[0],
						getPublicKey(sha256('another parent key'))
					]),
				text: T.keys
			},
			{
				what: 'a plain parent whose funding script commits to a root',
				in: TO_ASSET,
				spec: (s): unknown => (s.scriptRoot = SAMPLE_ROOT),
				text: T.keys
			},
			{
				what: 'an asset parent whose funding script commits to another root',
				in: TO_PLAIN,
				spec: (s): unknown => (s.scriptRoot = sha256('another root')),
				text: T.keys
			},
			{
				what: 'an asset parent root one bit off',
				in: TO_PLAIN,
				layout: (l): unknown => (l.parentRoot = flip(l.parentRoot!)),
				text: T.keys
			},
			{
				what: 'an asset parent without its root',
				in: TO_PLAIN,
				layout: (l): unknown => delete l.parentRoot,
				text: T.keys
			},
			{
				what: "an expected parent value one sat off the parent output's",
				in: BOTH,
				expectation: (x): unknown =>
					(x.parentValueSats = x.parentValueSats + 1n),
				text: T.keys
			}
		]);
	});

	describe('check 3, the serials', () => {
		runCases('check 3', [
			{
				what: 'no input',
				in: BOTH,
				layout: (l): unknown => (l.inputs = []),
				text: T.count
			},
			{
				what: 'no output',
				in: BOTH,
				layout: (l): unknown => (l.outputs = []),
				text: T.count
			},
			{
				what: '253 outputs',
				in: BOTH,
				layout: (l): unknown =>
					(l.outputs = [
						...l.outputs,
						...Array.from({ length: 253 - l.outputs.length }, (_, k) => ({
							serialId: 1000n + 2n * BigInt(k),
							role: 'change' as const,
							amountSats: 1000n,
							descriptorHash: sha256('extra ' + k)
						}))
					]),
				text: T.count
			},
			{
				what: 'two outputs out of order',
				in: BOTH,
				layout: (l): unknown => (l.outputs = [...l.outputs].reverse()),
				text: T.serial
			},
			{
				what: "a change serial one bit off, reusing the seller's input serial",
				in: TO_ASSET,
				layout: (l, s): unknown => (outputOf(l, s, 'change').serialId ^= 2n),
				text: T.serial
			},
			{
				what: "a withdrawal serial one bit off, reusing the shared input's",
				in: TO_PLAIN,
				layout: (l, s): unknown => (outputOf(l, s, 'w1').serialId ^= 4n),
				text: T.serial
			},
			{
				what: 'a serial above u64',
				in: BOTH,
				layout: (l): unknown => (lastOwnOutput(l).serialId = 2n ** 64n),
				text: T.serial
			},
			{
				what: 'two outputs with one serial',
				in: BOTH,
				layout: (l): unknown =>
					(l.outputs = [
						...l.outputs,
						{
							...l.outputs[l.outputs.length - 1],
							descriptorHash: sha256('twin')
						}
					]),
				text: T.serial
			}
		]);
	});

	describe('check 4, the inputs', () => {
		runCases('check 4', [
			{
				what: 'the shared input owned by the acceptor (its serial one bit off)',
				in: BOTH,
				layout: (l, s): unknown => (inputOf(l, s, 'shared').serialId ^= 1n),
				text: T.shared
			},
			{
				what: 'a shared input of a parent txid one bit off',
				in: BOTH,
				layout: (l, s): void => {
					const i = inputOf(l, s, 'shared');
					i.prevTxid = flip(i.prevTxid);
				},
				text: T.shared
			},
			{
				what: 'a shared input of another output index',
				in: BOTH,
				layout: (l, s): unknown =>
					(inputOf(l, s, 'shared').prevOutputIndex = 0),
				text: T.shared
			},
			{
				what: 'a shared input carrying a previous transaction',
				in: BOTH,
				layout: (l, s): unknown =>
					(inputOf(l, s, 'shared').prevTx = l.parent.toBuffer()),
				text: T.shared
			},
			{
				what: 'a second shared input',
				in: BOTH,
				layout: (l): unknown =>
					(l.inputs = [
						...l.inputs,
						{
							serialId: 100n,
							prevTxid: sha256('another shared input'),
							prevOutputIndex: 0,
							sequence: 0xfffffffd,
							isShared: true
						}
					]),
				text: T.shared
			},
			{
				what: 'no shared input (an external coin in its place)',
				in: BOTH,
				layout: (l, s): void => {
					const coin = sampleCoin(30_000n, 'in place');
					l.inputs = l.inputs.map((i) =>
						i.serialId === s.serialOf('shared')
							? {
									serialId: i.serialId,
									prevTxid: coin.getHash(),
									prevOutputIndex: 0,
									sequence: 0xfffffffd,
									prevTx: coin.toBuffer(),
									isShared: false
							  }
							: i
					);
				},
				text: T.shared
			},
			{
				what: 'an external input without its previous transaction',
				in: TO_ASSET,
				layout: (l, s): unknown => delete inputOf(l, s, 'coin').prevTx,
				text: T.external
			},
			{
				what: 'an external input spending a non-segwit output',
				in: TO_ASSET,
				layout: (l, s): void => {
					const coin = sampleCoin(20_000n, 'legacy');
					coin.outs[0].script = Buffer.concat([
						Buffer.from('76a914', 'hex'),
						sha256('legacy').subarray(0, 20),
						Buffer.from('88ac', 'hex')
					]);
					const i = inputOf(l, s, 'coin');
					i.prevTx = coin.toBuffer();
					i.prevTxid = coin.getHash();
				},
				text: T.external
			},
			{
				what: "an external input index past its previous transaction's outputs",
				in: TO_ASSET,
				layout: (l, s): unknown => (inputOf(l, s, 'coin').prevOutputIndex = 1),
				text: T.external
			},
			{
				what: 'an external previous transaction that does not hash to its txid',
				in: TO_ASSET,
				layout: (l, s): void => {
					const i = inputOf(l, s, 'coin');
					i.prevTxid = flip(i.prevTxid);
				},
				text: T.mismatch
			},
			{
				what: 'a sequence above 0xfffffffd',
				in: BOTH,
				layout: (l, s): unknown =>
					(inputOf(l, s, 'shared').sequence = 0xfffffffe),
				text: T.input
			},
			{
				what: 'two inputs spending one outpoint',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(l.inputs = [
						...l.inputs,
						{ ...inputOf(l, s, 'coin'), serialId: s.serialOf('coin') + 100n }
					]),
				text: T.input
			}
		]);
	});

	describe('check 5, the output amounts', () => {
		runCases('check 5', [
			{
				what: 'a withdrawal one sat below the larger candidate dust limit',
				in: TO_PLAIN,
				layout: (l, s): unknown => (outputOf(l, s, 'w1').amountSats -= 1n),
				text: T.amount
			},
			{
				what: 'a change output at 546 sats, above both dust limits',
				in: TO_ASSET,
				spec: (s): unknown => sellerChange(s, 546n + 1500n, 1500n),
				text: undefined
			},
			{
				what: 'a change output at 545 sats',
				in: TO_ASSET,
				spec: (s): unknown => sellerChange(s, 546n + 1500n, 1500n),
				layout: (l, s): unknown => (outputOf(l, s, 'change').amountSats -= 1n),
				text: T.amount
			},
			{
				what: 'an output one sat above MAX_MONEY',
				in: BOTH,
				layout: (l): unknown =>
					(lastOwnOutput(l).amountSats = MAX_MONEY_SATS + 1n),
				text: T.amount
			},
			{
				what: 'outputs whose running total passes MAX_MONEY',
				in: BOTH,
				layout: (l): unknown => (lastOwnOutput(l).amountSats = MAX_MONEY_SATS),
				text: T.amount
			}
		]);
	});

	describe('check 6, the funding output', () => {
		runCases('check 6', [
			{
				what: 'a funding output one sat above the capacity',
				in: BOTH,
				layout: (l, s): unknown => (outputOf(l, s, 'funding').amountSats += 1n),
				text: T.funding
			},
			{
				what: 'a funding output one sat below the capacity',
				in: BOTH,
				layout: (l, s): unknown => (outputOf(l, s, 'funding').amountSats -= 1n),
				text: T.funding
			},
			{
				what: 'a funding output of the acceptor (its serial one bit off)',
				in: BOTH,
				layout: (l, s): unknown => (outputOf(l, s, 'funding').serialId ^= 1n),
				text: T.funding
			},
			{
				what: 'a second funding output',
				in: BOTH,
				layout: (l): unknown => (lastOwnOutput(l).role = 'funding'),
				text: T.funding
			},
			{
				what: 'no funding output',
				in: BOTH,
				layout: (l, s): unknown => (outputOf(l, s, 'funding').role = 'change'),
				text: T.funding
			},
			{
				what: 'an output of an unknown role',
				in: BOTH,
				layout: (l): unknown =>
					(lastOwnOutput(l).role = 'swap' as unknown as 'change'),
				text: T.role
			},
			{
				what: 'a withdrawal output to an asset',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(outputOf(l, s, 'change').role = 'withdrawal'),
				text: T.role
			}
		]);
	});

	describe('check 7, the fees', () => {
		runCases('check 7', [
			{
				what: "the seller's fee one sat above its budget",
				in: TO_ASSET,
				layout: (l, s): unknown => (outputOf(l, s, 'change').amountSats -= 1n),
				text: T.fees
			},
			{
				what: "the seller's fee at zero",
				in: TO_ASSET,
				spec: (s): unknown => sellerChange(s, 20_000n, 0n),
				text: undefined
			},
			{
				what: "the seller's fee one sat below zero",
				in: TO_ASSET,
				spec: (s): unknown => sellerChange(s, 20_000n, 0n),
				layout: (l, s): unknown => (outputOf(l, s, 'change').amountSats += 1n),
				text: T.fees
			},
			{
				what: "the buyer's fee one sat above its budget",
				in: TO_PLAIN,
				layout: (l, s): unknown => (outputOf(l, s, 'w2').amountSats -= 1n),
				text: T.fees
			},
			{
				what: "the buyer's fee at zero",
				in: TO_PLAIN,
				spec: (s): unknown =>
					(s.outputs.find((o) => o.key === 'w2')!.amount = 3200n),
				text: undefined
			},
			{
				what: "the buyer's fee one sat below zero",
				in: TO_PLAIN,
				spec: (s): unknown =>
					(s.outputs.find((o) => o.key === 'w2')!.amount = 3200n),
				layout: (l, s): unknown => (outputOf(l, s, 'w2').amountSats += 1n),
				text: T.fees
			}
		]);
	});

	describe('check 8, the first commitment', () => {
		runCases('check 8', [
			{
				what: 'first commitment balances one msat above the capacity',
				in: BOTH,
				spec: (s): unknown => (s.firstBalances.acceptor += 1n),
				text: T.first,
				roles: true
			},
			{
				what: 'first commitment balances one msat below the capacity',
				in: BOTH,
				spec: (s): unknown => (s.firstBalances.opener -= 1n),
				text: T.first,
				roles: true
			}
		]);
	});

	describe('check 10, the units', () => {
		const TOO_BIG = 2n ** 64n;
		runCases('check 10', [
			{
				what: 'a movement of an asset the terms do not name',
				in: BOTH,
				layout: (l): unknown => (l.movements[0].assetId = '33'.repeat(32)),
				text: T.units
			},
			{
				what: 'an asset id in upper case',
				in: BOTH,
				layout: (l): unknown =>
					(l.movements[0].assetId = l.movements[0].assetId.toUpperCase()),
				text: T.units
			},
			{
				what: 'a movement of zero units',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_A, 'change').units = 0n),
				text: T.units
			},
			{
				what: 'a movement of zero units',
				in: TO_PLAIN,
				layout: (l, s): unknown => (movementOf(l, s, ASSET_A, 'w1').units = 0n),
				text: T.units
			},
			{
				what: 'a movement above u64',
				in: BOTH,
				layout: (l): unknown => (l.movements[0].units = TOO_BIG),
				text: T.units
			},
			{
				what: 'two movements with one asset, holder and output',
				in: TO_ASSET,
				layout: (l, s): void => {
					const m = movementOf(l, s, ASSET_A, 'funding');
					l.movements = [...l.movements, { ...m, units: 400n }];
					m.units -= 400n;
				},
				text: T.units
			},
			{
				what: 'two movements with one asset, holder and output',
				in: TO_PLAIN,
				layout: (l, s): void => {
					const m = movementOf(l, s, ASSET_B, 'w2');
					l.movements = [...l.movements, { ...m, units: 250n }];
					m.units -= 250n;
				},
				text: T.units
			},
			{
				what: 'parent units to an asset',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.parentUnits = [
						{ assetId: ASSET_A, initiator: 0n, acceptor: 1000n }
					]),
				text: T.units
			},
			{
				what: 'a movement from the buyer',
				in: TO_ASSET,
				layout: (l, s): void => {
					const m = movementOf(l, s, ASSET_B, 'funding');
					m.from = m.from === 'initiator' ? 'acceptor' : 'initiator';
				},
				text: T.units,
				roles: true
			},
			{
				what: 'funding movements one unit short of an issuance',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_B, 'funding').units -= 1n),
				text: T.units
			},
			{
				what: 'funding movements one unit over an issuance',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_A, 'funding').units += 1n),
				text: T.units
			},
			{
				what: 'a movement to an output that is not change',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_A, 'change').outputSerial =
						s.serialOf('change') + 100n),
				text: T.units
			},
			{
				what: 'no commitment record limits',
				in: TO_ASSET,
				layout: (l): unknown => (l.commitmentRecordLimits = null),
				text: T.units
			},
			{
				what: "one holder's commitment record limits only",
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.commitmentRecordLimits = [
						l.commitmentRecordLimits![0]
					] as unknown as IConversionLayout['commitmentRecordLimits']),
				text: T.units
			},
			{
				what: 'record limits without the 65537 record',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.commitmentRecordLimits = [
						[{ type: 65539n, maxBytes: 10 }],
						l.commitmentRecordLimits![1]
					]),
				text: 'Incomplete asset splice commitment limits'
			},
			{
				what: 'a negative record limit',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.commitmentRecordLimits = [
						l.commitmentRecordLimits![0],
						[{ type: 65537n, maxBytes: -1 }]
					]),
				text: 'Invalid asset splice signature record limits'
			},
			{
				what: 'record limits past the commitment payload',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.commitmentRecordLimits = [
						[{ type: 65537n, maxBytes: 60_000 }],
						l.commitmentRecordLimits![1]
					]),
				text: (s): string => {
					try {
						assetSpliceCommitmentBytes(
							s.layout.candidateMaxAcceptedHtlcs as [number, number],
							[{ type: 65537n, maxBytes: 60_000 }]
						);
					} catch (error) {
						return (error as Error).message;
					}
					return 'the sample should overflow the payload';
				}
			},
			{
				what: 'a candidate HTLC limit of 84',
				in: TO_ASSET,
				spec: (s): unknown => (s.htlcs.opener = 84),
				text: 'Incomplete asset splice commitment limits'
			},
			{
				what: 'parent units missing an issuance',
				in: TO_PLAIN,
				layout: (l): unknown =>
					(l.parentUnits = l.parentUnits.filter((u) => u.assetId !== ASSET_B)),
				text: T.units
			},
			{
				what: 'parent units naming another asset',
				in: TO_PLAIN,
				layout: (l): unknown =>
					(l.parentUnits = [
						...l.parentUnits,
						{ assetId: '33'.repeat(32), initiator: 1n, acceptor: 0n }
					]),
				text: T.units
			},
			{
				what: 'parent units one unit above an issuance',
				in: TO_PLAIN,
				layout: (l): unknown => (l.parentUnits[0].initiator += 1n),
				text: T.units
			},
			{
				what: 'parent units out of order',
				in: TO_PLAIN,
				layout: (l): unknown => (l.parentUnits = [...l.parentUnits].reverse()),
				text: T.units
			},
			{
				what: 'parent units naming one asset twice',
				in: TO_PLAIN,
				layout: (l): unknown =>
					(l.parentUnits = [
						{ ...l.parentUnits[0], initiator: 0n, acceptor: 0n },
						...l.parentUnits
					]),
				text: T.units
			},
			{
				what: 'a negative parent unit',
				in: TO_PLAIN,
				layout: (l): void => {
					l.parentUnits[0].initiator -= l.parentUnits[0].initiator + 1n;
					l.parentUnits[0].acceptor += 301n;
				},
				text: T.units
			},
			{
				what: 'a parent unit above u64',
				in: TO_PLAIN,
				layout: (l): void => {
					l.parentUnits[0].initiator = TOO_BIG;
					l.parentUnits[0].acceptor = 1000n - TOO_BIG;
				},
				text: T.units
			},
			{
				what: 'an issuance that nobody holds a unit of',
				in: TO_PLAIN,
				spec: (s): void => {
					s.issuances[1].amount = 0n;
					s.parentUnits[1] = { assetId: ASSET_B, opener: 0n, acceptor: 0n };
					s.movements = s.movements.filter((m) => m.assetId !== ASSET_B);
				},
				text: T.units
			},
			{
				what: 'movements one unit short of an issuance',
				in: TO_PLAIN,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_A, 'w2').units -= 1n),
				text: T.units
			},
			{
				what: "movements that take one unit from the other holder's share",
				in: TO_PLAIN,
				layout: (l, s): void => {
					const w1 = l.movements.filter(
						(m) => m.assetId === ASSET_A && m.outputSerial === s.serialOf('w1')
					);
					w1[0].units -= 1n;
					w1[1].units += 1n;
				},
				text: T.units,
				roles: true
			},
			{
				what: 'a movement to the funding output',
				in: TO_PLAIN,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_B, 'w2').outputSerial =
						s.serialOf('funding')),
				text: T.units
			},
			{
				what: 'commitment record limits to bitcoin',
				in: TO_PLAIN,
				layout: (l): unknown =>
					(l.commitmentRecordLimits = [
						[{ type: 65537n, maxBytes: 1000 }],
						[{ type: 65537n, maxBytes: 1000 }]
					]),
				text: T.units
			}
		]);
	});

	describe('check 11, credits by parity', () => {
		/** To an asset, the buyer (the opener) adds a change output its contribution pays for. */
		const buyerChange = (s: ILayoutSpec): void => {
			s.contributions.opener = -1000n;
			s.outputs.find((o) => o.key === 'funding')!.amount -= 1000n;
			s.outputs.splice(1, 0, {
				key: 'buyerChange',
				owner: 'opener',
				role: 'change',
				serial: 4n,
				amount: 1000n
			});
			s.firstBalances.opener -= 1_000_000n;
		};
		/** To bitcoin, the seller (the acceptor) withdraws too, from its contribution. */
		const sellerWithdraws = (s: ILayoutSpec): void => {
			s.contributions.acceptor = -1000n;
			s.outputs.find((o) => o.key === 'funding')!.amount -= 1000n;
			s.outputs.splice(2, 0, {
				key: 'sellerW',
				owner: 'acceptor',
				role: 'withdrawal',
				serial: 5n,
				amount: 1000n
			});
			s.firstBalances.acceptor -= 1_000_000n;
		};
		runCases('check 11', [
			{
				what: "the buyer's own change output, its units with the seller",
				in: TO_ASSET,
				spec: buyerChange,
				text: undefined,
				roles: true
			},
			{
				what: "the seller's change units credited to the buyer's change output",
				in: TO_ASSET,
				spec: buyerChange,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_A, 'change').outputSerial =
						s.serialOf('buyerChange')),
				text: T.credit,
				roles: true
			},
			{
				what: "the seller's own withdrawal, every unit with the buyer",
				in: TO_PLAIN,
				spec: sellerWithdraws,
				text: undefined,
				roles: true
			},
			{
				what: "units credited to the seller's withdrawal",
				in: TO_PLAIN,
				spec: sellerWithdraws,
				layout: (l, s): unknown =>
					(movementOf(l, s, ASSET_B, 'w2').outputSerial =
						s.serialOf('sellerW')),
				text: T.credit,
				roles: true
			}
		]);
	});

	describe('check 12, the reserves and the trade rule', () => {
		const capacity = (s: ILayoutSpec): bigint =>
			s.parentValue + s.contributions.opener + s.contributions.acceptor;
		/** The buyer to bitcoin (the opener) exactly at its reserve and fees. */
		const buyerAtFloor = (s: ILayoutSpec, less = 0n): void => {
			const c = capacity(s);
			const reserve = finalFundingReserveSats(c, policy(s), true);
			expect(finalFundingReserveSats(c, policy(s), false)).to.equal(reserve);
			balances(
				s,
				s.parentBalances.opener,
				reserve * 1000n + costMsat(s) - less
			);
		};
		/** To an asset, the opener sells, and the acceptor buys with no output of its own. */
		const tradeToAsset = (s: ILayoutSpec, paid: bigint): void => {
			openerSells(s);
			balances(s, 199_000_000n, 199_000_000n + paid);
		};
		/** To bitcoin, the acceptor sells with no output of its own. */
		const tradeToPlain = (s: ILayoutSpec, paid: bigint): void =>
			balances(s, 199_000_000n, 194_800_000n + paid);
		/** The opener holds no output and no unit, its balance covering only its fees. */
		const openerAtCost = (s: ILayoutSpec, less: bigint): void => {
			s.firstUnits = s.firstUnits.map((u) => ({
				assetId: u.assetId,
				opener: 0n,
				acceptor: u.opener + u.acceptor
			}));
			balances(s, costMsat(s), costMsat(s) - less);
		};
		runCases('check 12', [
			{
				what: 'the buyer exactly at its reserve and the commitment fee',
				in: TO_PLAIN,
				spec: (s): unknown => buyerAtFloor(s),
				text: undefined,
				roles: true
			},
			{
				what: 'the buyer one msat below its reserve and the commitment fee',
				in: TO_PLAIN,
				spec: (s): unknown => buyerAtFloor(s, 1n),
				text: T.reserve,
				roles: true
			},
			{
				what: "a side with no output below the reserve, its balance at its parent's",
				in: TO_ASSET,
				spec: (s): unknown => tradeToAsset(s, 0n),
				text: undefined,
				roles: true
			},
			{
				what: "a side with no output below the reserve, one msat below its parent's (the trade rule)",
				in: TO_ASSET,
				spec: (s): unknown => tradeToAsset(s, 1n),
				text: T.reserve,
				roles: true
			},
			{
				what: "a side with no output below the reserve, its balance at its parent's",
				in: TO_PLAIN,
				spec: (s): unknown => tradeToPlain(s, 0n),
				text: undefined,
				roles: true
			},
			{
				what: "a side with no output below the reserve, one msat below its parent's (the trade rule)",
				in: TO_PLAIN,
				spec: (s): unknown => tradeToPlain(s, 1n),
				text: T.reserve,
				roles: true
			},
			{
				what: 'the opener, with no output, exactly at the commitment fee and anchors',
				in: TO_ASSET,
				spec: (s): unknown => openerAtCost(s, 0n),
				text: undefined,
				roles: true
			},
			{
				what: 'the opener, with no output, one msat below the commitment fee and anchors',
				in: TO_ASSET,
				spec: (s): unknown => openerAtCost(s, 1n),
				text: T.reserve,
				roles: true
			}
		]);
	});

	describe('check 13, the carriers to an asset', () => {
		/** The opener sells; the acceptor buys units with no output, pushed `push` msat. */
		const acceptorCarries = (s: ILayoutSpec, push: bigint): void => {
			openerSells(s);
			s.dust = { opener: 354n, acceptor: 400n };
			s.firstUnits = [
				{ assetId: ASSET_A, opener: 0n, acceptor: 1000n },
				{ assetId: ASSET_B, opener: 500n, acceptor: 0n }
			];
			balances(
				s,
				s.parentValue * 1000n - 399_999n,
				s.parentValue * 1000n - push
			);
		};
		/** The opener holds units with no output and keeps `kept` msat. */
		const openerCarries = (s: ILayoutSpec, kept: bigint): void => {
			const floor = (354n + carrierCostSats(s)) * 1000n;
			balances(s, floor - 1n, kept);
		};
		const carrierText = (s: ISample): string => auxiliaryCarrierErrorText(s);
		runCases('check 13', [
			{
				what: 'the acceptor holding units pushed exactly the larger dust limit',
				in: TO_ASSET,
				spec: (s): unknown => acceptorCarries(s, 400_000n),
				text: undefined,
				roles: true
			},
			{
				what: 'the acceptor holding units pushed one msat below the larger dust limit',
				in: TO_ASSET,
				spec: (s): unknown => acceptorCarries(s, 399_999n),
				text: 'The acceptor of an asset channel holds asset units and has to be pushed at least 400 satoshis to carry them',
				roles: true
			},
			{
				what: 'the opener holding units with exactly the dust limit after the fee and anchors',
				in: TO_ASSET,
				spec: (s): unknown =>
					openerCarries(s, (354n + carrierCostSats(s)) * 1000n),
				text: undefined,
				roles: true
			},
			{
				what: 'the opener holding units with one msat less',
				in: TO_ASSET,
				spec: (s): unknown =>
					openerCarries(s, (354n + carrierCostSats(s)) * 1000n - 1n),
				text: carrierText,
				roles: true
			}
		]);
	});
});

/** The opener's carrier text for a sample, by auxiliaryCarrierError itself. */
function auxiliaryCarrierErrorText(s: ISample): string {
	const t = s.terms.firstCommitment;
	const sum = (role: 'opener' | 'acceptor'): bigint =>
		(t.units ?? []).reduce((a, u) => a + BigInt(u[role]), 0n);
	const text = auxiliaryCarrierError({
		fundingSatoshis:
			s.spec.parentValue +
			s.spec.contributions.opener +
			s.spec.contributions.acceptor,
		pushMsat: BigInt(t.balanceMsat.acceptor),
		feeratePerKw: t.commitmentFeeratePerKw,
		openerAssetBalance: sum('opener'),
		acceptorAssetBalance: sum('acceptor'),
		dustLimitSatoshis:
			s.spec.dust.opener > s.spec.dust.acceptor
				? s.spec.dust.opener
				: s.spec.dust.acceptor
	});
	expect(text, 'the sample breaks the carrier rule').to.match(
		/^The opener of an asset channel/
	);
	return text!;
}

describe('The asset conversion layout digest (#2151 step 3b, section 4)', () => {
	const digestOf = (l: IConversionLayout): Buffer =>
		conversionLayout().assetConversionLayoutDigest(l);
	const PINS: Record<Direction, string> = {
		'to-asset':
			'1d74c2b65b51eac70a75319834dbb76d215ab1eb237eefdff4bf715c9493ce9a',
		'to-plain':
			'ce2d858e172327b335dc324e6cc2ff56392a83d1940a299a987337302ae95595'
	};

	for (const direction of BOTH) {
		it(`pins the bytes of the ${direction} sample layout`, () => {
			const { layout } = buildSample(specOf(direction));
			expect(layoutDigestOf(layout).toString('hex'), 'the formula').to.equal(
				PINS[direction]
			);
			expect(digestOf(layout).toString('hex')).to.equal(PINS[direction]);
		});

		it(`is invariant to the order of the movements (${direction})`, () => {
			const { layout } = buildSample(specOf(direction));
			layout.movements = [...layout.movements].reverse();
			expect(digestOf(layout).toString('hex')).to.equal(PINS[direction]);
		});

		it(`changes with one unit of one movement (${direction})`, () => {
			const { layout } = buildSample(specOf(direction));
			layout.movements[0].units += 1n;
			expect(digestOf(layout).toString('hex')).to.equal(
				layoutDigestOf(layout).toString('hex')
			);
			expect(digestOf(layout).toString('hex')).to.not.equal(PINS[direction]);
		});
	}

	it("hashes each holder's record limits sorted by type", () => {
		const { layout } = buildSample(specOf('to-asset'));
		const [own, other] = layout.commitmentRecordLimits!;
		layout.commitmentRecordLimits = [[...own].reverse(), other];
		expect(digestOf(layout).toString('hex')).to.equal(PINS['to-asset']);
	});

	it('binds the target type to the layout: the plain type to bitcoin', () => {
		const { layout } = buildSample(specOf('to-plain'));
		expect(layout.targetType.toString('hex')).to.equal(PLAIN_TARGET_TYPE_HEX);
		expect(digestOf(layout).toString('hex')).to.equal(PINS['to-plain']);
	});
});

describe('Asset conversion layout guards (#2151 step 3b, section 4 checks 1, 2, 4 and 10)', function () {
	describe('check 1, the fields the engine fills from the terms', () => {
		runCases('check 1', [
			{
				what: "a channel id other than the terms', which both splice messages carry",
				in: BOTH,
				layout: (l): void => {
					const other = flip(l.channelId);
					l.channelId = other;
					reinit(l, (m) => (m.channelId = other));
					reack(l, (m) => (m.channelId = other));
				},
				text: T.layout
			},
			{
				what: 'a first commitment that leaves out the last units row of the terms',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.firstCommitment = {
						...l.firstCommitment,
						units: l.firstCommitment.units.slice(0, -1)
					}),
				text: T.layout
			},
			{
				what: 'a first commitment with no units row, to an asset',
				in: TO_ASSET,
				layout: (l): unknown =>
					(l.firstCommitment = { ...l.firstCommitment, units: [] }),
				text: T.layout
			}
		]);
	});

	describe('check 2, the parent output', () => {
		runCases('check 2', [
			{
				what: "a parent transaction with no output at the terms' index (its id kept)",
				in: BOTH,
				layout: (l): void => {
					const id = l.parent.getId();
					const hash = l.parent.getHash();
					const parent = l.parent.clone();
					parent.outs.splice(l.parentIndex);
					parent.getId = (): string => id;
					parent.getHash = (): Buffer => Buffer.from(hash);
					l.parent = parent;
				},
				text: T.keys
			},
			{
				what: 'a plain parent that carries a root, which its script never uses',
				in: TO_ASSET,
				layout: (l): unknown => (l.parentRoot = SAMPLE_ROOT),
				text: undefined
			}
		]);
	});

	describe("check 4, the asset splice's input rules", () => {
		/** A coin of `value` sats whose previous transaction is `size` bytes or more. */
		const bigCoin = (value: bigint, tag: string, size: number): Transaction => {
			const coin = sampleCoin(value, tag);
			coin.addOutput(Buffer.alloc(size, 0x6a), 0);
			return coin;
		};
		/** The coin's bytes with its input count as a three-byte varint: the same txid. */
		const nonMinimal = (coin: Transaction): Buffer => {
			const b = coin.toBuffer();
			return Buffer.concat([
				b.subarray(0, 4),
				Buffer.from([0xfd, 1, 0]),
				b.subarray(5)
			]);
		};
		runCases('check 4', [
			{
				what: 'a 31-byte previous txid',
				in: BOTH,
				layout: (l, s): void => {
					const i = inputOf(l, s, 'shared');
					i.prevTxid = i.prevTxid.subarray(0, 31);
				},
				text: T.input
			},
			{
				what: 'an external input index of 2^32',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(inputOf(l, s, 'coin').prevOutputIndex = 0x100000000),
				text: T.input
			},
			{
				what: 'an external input index of -1',
				in: TO_ASSET,
				layout: (l, s): unknown => (inputOf(l, s, 'coin').prevOutputIndex = -1),
				text: T.input
			},
			{
				what: 'a fractional external input index',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					(inputOf(l, s, 'coin').prevOutputIndex = 0.5),
				text: T.input
			},
			{
				what: 'a fractional sequence',
				in: BOTH,
				layout: (l, s): unknown => (inputOf(l, s, 'shared').sequence = 1.5),
				text: T.input
			},
			{
				what: 'a negative sequence',
				in: BOTH,
				layout: (l, s): unknown => (inputOf(l, s, 'shared').sequence = -1),
				text: T.input
			},
			{
				what: 'a prevTxVout other than the input index',
				in: BOTH,
				layout: (l, s): void => {
					const i = inputOf(l, s, 'shared');
					i.prevTxVout = i.prevOutputIndex + 1;
				},
				text: T.input
			},
			{
				what: 'an external input whose isShared is neither a boolean nor absent',
				in: TO_ASSET,
				layout: (l, s): unknown =>
					((inputOf(l, s, 'coin') as { isShared?: unknown }).isShared = 1),
				text: T.external
			},
			{
				what: 'an external previous transaction over 65,535 bytes',
				in: TO_ASSET,
				layout: (l, s): void => {
					const coin = bigCoin(20_000n, 'coin', 65_536);
					const i = inputOf(l, s, 'coin');
					i.prevTx = coin.toBuffer();
					i.prevTxid = coin.getHash();
				},
				text: T.external
			},
			{
				what: "one owner's previous transactions over 1 MiB in all",
				in: TO_ASSET,
				layout: (l, s): void => {
					const owner = s.serialOf('coin') & 1n;
					const extra = Array.from({ length: 17 }, (_, n) => {
						const coin = bigCoin(1_000n, 'heavy ' + n, 65_000);
						return {
							serialId: 100n + 2n * BigInt(n) + owner,
							prevTxid: coin.getHash(),
							prevOutputIndex: 0,
							sequence: 0xfffffffd,
							prevTx: coin.toBuffer(),
							isShared: false
						};
					});
					l.inputs = [...l.inputs, ...extra];
				},
				text: T.external
			},
			{
				what: 'an external previous transaction in a non-canonical encoding of its txid',
				in: TO_ASSET,
				layout: (l, s): void => {
					const i = inputOf(l, s, 'coin');
					const coin = Transaction.fromBuffer(i.prevTx!);
					i.prevTx = nonMinimal(coin);
					expect(Transaction.fromBuffer(i.prevTx).getHash()).to.deep.equal(
						i.prevTxid
					);
				},
				text: T.mismatch
			}
		]);
	});

	describe('check 10, the movements', () => {
		runCases('check 10', [
			{
				what: "a movement whose from is a String object, not the union's string",
				in: TO_PLAIN,
				layout: (l): void => {
					const m = l.movements[0] as { from: unknown };
					m.from = Object(m.from) as unknown;
				},
				text: T.units
			}
		]);
	});
});

describe('From the description to the layout (#2151 step 3b, section 3 S15 and v2.4 item 2)', () => {
	const DESCRIBE = 'Asset conversion host could not describe the layout';
	type Record_ = Record<string, unknown>;
	/** The sample's engine fields, its expectation and the description it maps from. */
	function parts(direction: Direction): {
		sample: ISample;
		base: IConversionLayoutBase;
		x: IConversionLayoutExpectation;
		description: Record_ & {
			inputs: Record_[];
			outputs: Record_[];
		};
	} {
		const sample = buildSample(specOf(direction));
		const {
			commitmentRecordLimits,
			parentUnits,
			movements,
			inputs,
			outputs,
			...base
		} = sample.layout;
		const x = sample.expectations[0];
		const description = {
			inputs: inputs.map(
				(i): Record_ => ({
					serialId: i.serialId,
					txid: Buffer.from(i.prevTxid),
					vout: i.prevOutputIndex,
					sequence: i.sequence,
					isShared: i.isShared === true,
					...(i.prevTx !== undefined && { prevTx: Buffer.from(i.prevTx) })
				})
			),
			outputs: outputs.map(
				(o): Record_ => ({
					serialId: o.serialId,
					kind: o.role,
					valueSats: o.amountSats,
					descriptorHash: Buffer.from(o.descriptorHash)
				})
			),
			movements: movements.map((m) => ({ ...m })),
			parentUnits: parentUnits.map((u) => ({ ...u })),
			feeBudgets: [...sample.layout.feeBudgets],
			relativeSatoshis: [...x.relativeSatoshis],
			...(commitmentRecordLimits !== null && {
				commitmentRecordLimits: commitmentRecordLimits.map((r) =>
					r.map((v) => ({ ...v }))
				)
			})
		};
		return { sample, base, x, description };
	}
	const mapped = (p: ReturnType<typeof parts>): IConversionLayout =>
		conversionLayout().describedConversionLayout(
			p.base,
			p.x.relativeSatoshis,
			p.description
		);
	/** The text describedConversionLayout throws, or undefined. */
	const thrown = (p: ReturnType<typeof parts>): string | undefined => {
		try {
			mapped(p);
			return undefined;
		} catch (error) {
			return error instanceof Error ? error.message : String(error);
		}
	};
	const digestOf = (l: IConversionLayout): Buffer =>
		conversionLayout().assetConversionLayoutDigest(l);

	for (const direction of BOTH)
		it(`maps the sample description to the sample layout (${direction})`, () => {
			const p = parts(direction);
			const layout = mapped(p);
			expect(verdict(layout, p.x)).to.equal(undefined);
			expect(digestOf(layout)).to.deep.equal(digestOf(p.sample.layout));
		});

	it('reads an output descriptorHash once: a 2-byte second answer cannot reach the layout', () => {
		const p = parts('to-plain');
		const o = p.description.outputs[p.description.outputs.length - 1];
		const good = o.descriptorHash as Buffer;
		let reads = 0;
		Object.defineProperty(o, 'descriptorHash', {
			enumerable: true,
			get: (): Buffer => (reads++ === 0 ? good : good.subarray(0, 2))
		});
		const layout = mapped(p);
		expect(layout.outputs.map((x) => x.descriptorHash.length)).to.deep.equal(
			layout.outputs.map(() => 32)
		);
		expect(reads, 'reads of the field').to.equal(1);
		expect(verdict(layout, p.x)).to.equal(undefined);
		expect(digestOf(layout)).to.deep.equal(digestOf(p.sample.layout));
	});

	it('reads the outputs list once: a second answer with 2-byte hashes cannot reach the layout', () => {
		const p = parts('to-plain');
		const good = p.description.outputs;
		const bad = good.map((o) => ({
			...o,
			descriptorHash: (o.descriptorHash as Buffer).subarray(0, 2)
		}));
		let reads = 0;
		Object.defineProperty(p.description, 'outputs', {
			enumerable: true,
			get: (): Record_[] => (reads++ === 0 ? good : bad)
		});
		const layout = mapped(p);
		expect(layout.outputs.map((x) => x.descriptorHash.length)).to.deep.equal(
			good.map(() => 32)
		);
		expect(reads, 'reads of the field').to.equal(1);
		expect(verdict(layout, p.x)).to.equal(undefined);
	});

	for (const direction of BOTH) {
		it(`gives the describe text for a sparse outputs array, not a TypeError (${direction})`, () => {
			const p = parts(direction);
			const holed = [...p.description.outputs];
			holed.length += 1;
			p.description.outputs = holed;
			expect(thrown(p)).to.equal(DESCRIBE);
		});

		it(`gives the describe text for an inputs array with a hole in the middle (${direction})`, () => {
			const p = parts(direction);
			const [first, ...rest] = p.description.inputs;
			const holed: Record_[] = [first];
			holed.length = 2;
			holed.push(...rest);
			p.description.inputs = holed;
			expect(thrown(p)).to.equal(DESCRIBE);
		});

		it(`gives the describe text for an input sequence that is not a safe integer (${direction})`, () => {
			const p = parts(direction);
			p.description.inputs[0].sequence = 1.5;
			expect(thrown(p)).to.equal(DESCRIBE);
		});
	}

	it('gives the describe text for a previous transaction that is hex, not a Buffer', () => {
		const p = parts('to-asset');
		const coin = p.description.inputs.find((i) => i.prevTx !== undefined)!;
		coin.prevTx = (coin.prevTx as Buffer).toString('hex');
		expect(thrown(p)).to.equal(DESCRIBE);
	});
});
