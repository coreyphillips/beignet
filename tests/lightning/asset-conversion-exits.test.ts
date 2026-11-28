/**
 * #2151 Step 4b, contract section 13, the exits file: after equal
 * `layout_ack`s both peers authorize the assets, freeze the funding, run the
 * construction, build and sign the candidate's first commitments, check and
 * retain both branches, and the initiator then sends the 4b fence; each side
 * drops its retained candidate and withdraws its attempt record
 * (`conversion-dropped`, then `conversion-withdrawn`), and the channel goes
 * on at its parent. Numbers in titles are the contract's (A1 to A29 of
 * section 13, then the V5 and V10 additions, then W2's burst).
 *
 * Three pairs serve most tests: plain to asset on a plain pair (N = 0),
 * asset to plain on an asset pair at k = 1 (N = 1) and at k = 0 (N = 0, V3).
 */
import { expect } from 'chai';
import { createHash, randomBytes } from 'crypto';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import type Database from 'better-sqlite3';
import BetterSqlite from 'better-sqlite3';
import type { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	buildAssetSpliceCommitment,
	buildFinalCommitmentView
} from '../../src/lightning/channel/final-opening-commitment';
import { finalSpliceFeeError } from '../../src/lightning/channel/final-splice-candidate';
import { finalSpliceSharedNonce } from '../../src/lightning/channel/final-splice-funding';
import { finalChannelOutputClaims } from '../../src/lightning/chain/final-output-claims';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import { deriveChannelKeys } from '../../src/lightning/keys/wallet-keys';
import { decodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import { encodeAssetOpenConsent } from '../../src/lightning/message/asset-open';
import {
	decodeTxCompleteMessage,
	encodeTxAddOutputMessage,
	encodeTxInitRbfMessage,
	encodeTxRemoveInputMessage,
	encodeTxSignaturesMessage
} from '../../src/lightning/message/interactive-tx';
import { MessageType } from '../../src/lightning/message/types';
import {
	createTaprootFundingScript,
	taprootKeySpendSighash
} from '../../src/lightning/script/funding-taproot';
import {
	branchCommitmentType,
	verifyPlainBranchWitness,
	type IFinalExitBranch
} from '../../src/lightning/storage/final-conversion-exits';
import {
	spliceCommitmentNonceContext,
	updateVerificationNonce
} from '../../src/lightning/storage/final-update-signing';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import type { IFinalFundingReference } from '../../src/lightning/channel/final-splice-candidate';
import { assetTypePair, scratch } from './helpers/channel-type-pairs';
import { deviceAuthority } from './helpers/channel-type-record';
import {
	attemptEvents,
	attemptRowCount,
	attemptStorage,
	conversionQuiet
} from './helpers/conversion-attempts';
import {
	abandoned,
	abortText,
	agreeOnTerms,
	assetSpliceCustom,
	attemptOf,
	conversionPair,
	conversionTransportOf,
	customPayload,
	decodeSpliceAck,
	decodeSpliceInit,
	enrolledAssetParent,
	expectFenceHostOrder,
	FENCE,
	frameOf,
	never,
	openingAssetBranch,
	openingRecordOf,
	PAIR_HEIGHT,
	parseFrame,
	PLAIN_TARGET_TYPE_HEX,
	rawFrame,
	roleOf,
	sharedPair,
	silenceConversion,
	STUB_WITHDRAWAL_SATS,
	startConversion,
	storeTerms,
	stubConversionDescription,
	stubExitEvidence,
	stubExitReceipt,
	stubFinalize,
	stubProposal,
	stubSellerCoin,
	tick,
	track,
	updateRound,
	type IConversionPair,
	type IWireMessage
} from './helpers/conversion-managers';
import type { IConversionExitReceipt } from './helpers/conversion-modules';
import {
	abortsFrom,
	branchRowsOf,
	candidateHash,
	capture,
	checkpointDigestOf,
	CONSTRUCTION_NAMES,
	conversionEvents,
	conversionKinds,
	conversionRowCount,
	defaultSigning,
	expectEnded,
	filesContaining,
	finalConversionsOf,
	finalDigestOf,
	flipFrameDigest,
	forgedCommitmentSigned,
	frameDigests,
	fundingsOf,
	gate,
	isConstruction,
	lastRowid,
	marks,
	OLD_FENCE,
	pendingConversionsOf,
	plantConversionEvent,
	refuseRepair,
	REUSED_TEXTS,
	scopeCounts,
	SIGNING_TEXTS,
	SRC_DIR,
	toPhase,
	walletDb
} from './helpers/conversion-signing';

const REF = Buffer.alloc(8, 0x4d);
const T = SIGNING_TEXTS;
const R = REUSED_TEXTS;
const HOST_BOUND_MS = 15_000;
const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
const hex = (b: Buffer | Uint8Array): string => Buffer.from(b).toString('hex');

type Key = 'plain' | 'asset1' | 'asset0';
const KIND: Record<Key, 'plain' | 'asset'> = {
	plain: 'plain',
	asset1: 'asset',
	asset0: 'asset'
};
const LABEL: Record<Key, string> = {
	plain: 'plain to asset',
	asset1: 'asset to plain at N = 1',
	asset0: 'asset to plain at N = 0'
};

/** Undo what a test changed on a shared pair's hosts and link. */
function clean(p: IConversionPair): void {
	p.link.clearRules();
	p.link.held.splice(0);
	p.link.taps.splice(0);
	p.hostLog.splice(0);
	for (const i of [0, 1] as const) {
		p.errors[i].splice(0);
		p.recycled[i].splice(0);
		const h = p.hosts[i];
		h.verify = (): unknown => true;
		h.abandon = (): unknown => undefined;
		h.propose = (): unknown => stubProposal(i);
		h.describe = (ctx, _proposals, bitcoin): unknown =>
			stubConversionDescription(ctx, h.termsFor(ctx), bitcoin);
		h.verifyExits = (ctx, views): unknown => stubExitEvidence(h, ctx, views);
		p.feerateEstimates[i] = async (): Promise<number> => 1000;
	}
	defaultSigning(p);
	agreeOnTerms(p);
}

/** End whatever a test left live: both sides disconnect and reconnect. */
async function reset(p: IConversionPair): Promise<void> {
	p.link.clearRules();
	p.link.held.splice(0);
	p.link.taps.splice(0);
	p.disconnect();
	await p.reconnect();
}

/** Side `I` starts and the link runs until idle. */
async function run(
	p: IConversionPair,
	I: 0 | 1 = 0
): Promise<ReturnType<typeof track>> {
	agreeOnTerms(p);
	const start = track(
		startConversion(p.managers[I], p.channelId, { reference: REF })
	);
	await p.settle();
	await start.done;
	return start;
}

const sentNames = (p: IConversionPair, from: 0 | 1, mark = 0): string[] =>
	p.link.sent
		.slice(mark)
		.filter((m) => m.from === from)
		.map((m) => m.name);
const findSent = (
	p: IConversionPair,
	from: 0 | 1,
	name: string,
	mark = 0
): IWireMessage | undefined =>
	p.link.sent.slice(mark).find((m) => m.from === from && m.name === name);
const quiet = (p: IConversionPair): boolean[] =>
	p.managers.map((m) => conversionQuiet(m, p.id));

/** The candidate keys of the splice_init and splice_ack on the wire, initiator first. */
function candidateKeys(
	p: IConversionPair,
	I: 0 | 1,
	mark: number
): [Buffer, Buffer] {
	const A = (1 - I) as 0 | 1;
	const init = decodeSpliceInit(findSent(p, I, 'SPLICE', mark)!.payload);
	const ack = decodeSpliceAck(findSent(p, A, 'SPLICE_ACK', mark)!.payload);
	return [init.fundingPubkey, ack.fundingPubkey];
}

/** The last attempt record of side i (its key index and digests). */
function lastRecord(
	store: SqliteStorage,
	id: string
): { keyIndex: number; attempt: string } {
	const records = attemptEvents(store, id).filter(
		(e) => e.kind === 'conversion-attempt'
	) as unknown as { keyIndex: number; attempt: string }[];
	return records[records.length - 1];
}

/**
 * The candidate's commitment facts on side i (4.1 and 4.2), computed here:
 * N, the terms' balances by role, the terms' feerate over the session's
 * terms, the points at N from the parent and the candidate's funding.
 */
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type -- the facts' shape is the builders' arguments
function candidateFacts(
	p: IConversionPair,
	i: 0 | 1,
	I: 0 | 1,
	mark: number,
	transaction: Buffer
) {
	const store = p.stores[i];
	const record = openingRecordOf(store, p.id);
	const terms = storeTerms(store, p.id, { reference: REF });
	const N = BigInt(terms.parent.stateNumber);
	const role = roleOf(store, p.id);
	const other = role === 'opener' ? 'acceptor' : 'opener';
	const balances = {
		localBalanceMsat: BigInt(terms.firstCommitment.balanceMsat[role]),
		remoteBalanceMsat: BigInt(terms.firstCommitment.balanceMsat[other])
	};
	const session = store.loadFinalOpeningSession(p.id)!;
	const candidateTerms = {
		...session.terms,
		commitmentFeeratePerKw: terms.firstCommitment.commitmentFeeratePerKw
	};
	let points: { local: Buffer; remote: Buffer };
	if (p.kind === 'plain') {
		const states = store.loadFinalResolutionStates(p.id)!;
		points = { local: states.local.point, remote: states.remote[0].point };
	} else {
		const parent = enrolledAssetParent(store, p.id, N);
		points = {
			local: Buffer.from(parent.localRecovery.point, 'hex'),
			remote: Buffer.from(parent.remoteRecovery.point, 'hex')
		};
	}
	const keys = candidateKeys(p, I, mark);
	const ours = i === I ? keys[0] : keys[1];
	const theirs = i === I ? keys[1] : keys[0];
	const frozen = Transaction.fromBuffer(transaction);
	const openingRoot = record.nonces.session.assetEvidence
		? Buffer.from(record.nonces.session.assetEvidence.fundingRoot, 'hex')
		: undefined;
	return {
		store,
		record,
		terms,
		N,
		balances,
		candidateTerms,
		points,
		keys,
		frozen,
		openingRoot,
		funding: (root?: Buffer): IFinalFundingReference => ({
			fundingTxHex: frozen.toHex(),
			fundingOutputIndex: frozen.outs.findIndex((o) =>
				o.script.equals(
					createTaprootFundingScript(keys[0], keys[1], undefined, root)
						.p2trOutput
				)
			),
			localFundingPubkey: hex(ours),
			remoteFundingPubkey: hex(theirs),
			localFundingKeyIndex: lastRecord(store, p.id).keyIndex
		})
	};
}

/** The refusal text of a local start, 'accepted', or a note that it never answered. */
async function refusal(start: () => unknown): Promise<string> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const out = await Promise.race([
			Promise.resolve().then(start),
			new Promise((done) => {
				timer = setTimeout(
					() => done({ ok: false, error: 'no answer within 2 s' }),
					2000
				);
			})
		]);
		const r = out as { ok?: boolean; error?: string } | undefined;
		return r && r.ok === false ? String(r.error) : 'accepted';
	} catch (e) {
		return (e as Error).message;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/** Claims as bytes: transactions and buffers as hex, functions left out. */
function claimBytes(claims: unknown): string {
	return JSON.stringify(claims, (_k, v: unknown) => {
		if (typeof v === 'function') return undefined;
		if (typeof v === 'bigint') return v.toString();
		if (v instanceof Transaction) return v.toHex();
		if (
			v &&
			typeof v === 'object' &&
			(v as { type?: string }).type === 'Buffer' &&
			Array.isArray((v as { data?: unknown }).data)
		)
			return Buffer.from((v as { data: number[] }).data).toString('hex');
		return v;
	});
}

describe('Asset conversion signs both exits up to the 4b fence (#2151 step 4b, section 13, the exits file)', function () {
	this.timeout(240000);
	const s = scratch('conversion-exits-');
	const used = new Set<Key>();
	const pairs: Record<Key, () => Promise<IConversionPair>> = {
		plain: sharedPair(s, 'plain'),
		asset1: sharedPair(s, 'asset', { rounds: 1 }),
		asset0: sharedPair(s, 'asset')
	};
	const shared = (key: Key): Promise<IConversionPair> => {
		used.add(key);
		return pairs[key]().then((p) => {
			clean(p);
			return p;
		});
	};
	const fresh = async (
		kind: 'plain' | 'asset' = 'plain',
		options?: Parameters<typeof conversionPair>[2]
	): Promise<IConversionPair> => {
		const p = await conversionPair(s, kind, options);
		clean(p);
		return p;
	};
	afterEach(async () => {
		sinon.restore();
		for (const key of [...used]) await reset(await pairs[key]());
		used.clear();
	});
	after(() => s.release());

	describe('The flow (A1 to A3)', () => {
		for (const I of [0, 1] as const)
			it(`A1. reaches the fence plain to asset with side ${I} initiating, through every host call in order`, async () => {
				const p = await shared('plain');
				const start = await run(p, I);
				expect(start.error, 'start').to.equal(undefined);
				expectFenceHostOrder(p.hostLog.slice(0), I);
				expect(abandoned(p, 0), 'side 0').to.deep.equal([FENCE]);
				expect(abandoned(p, 1), 'side 1').to.deep.equal([FENCE]);
			});

		for (const [key, I] of [
			['asset1', 0],
			['asset1', 1],
			['asset0', 0]
		] as const)
			it(`A2. reaches the fence ${LABEL[key]} with side ${I} initiating, through every host call in order`, async () => {
				const p = await shared(key);
				const start = await run(p, I);
				expect(start.error, 'start').to.equal(undefined);
				expectFenceHostOrder(p.hostLog.slice(0), I);
				expect(abandoned(p, 0), 'side 0').to.deep.equal([FENCE]);
				expect(abandoned(p, 1), 'side 1').to.deep.equal([FENCE]);
			});

		for (const [key, I] of [
			['plain', 0],
			['asset1', 1]
		] as const)
			it(`A3. sends each side's objects in section 1's order and nothing that signs the funding (${LABEL[key]}, side ${I} initiating)`, async () => {
				const p = await shared(key);
				const A = (1 - I) as 0 | 1;
				const c = capture(p);
				const mark = p.link.sent.length;
				await run(p, I);
				const skeleton = [
					'asset_splice:4',
					'asset_splice_consent',
					'asset_splice:1',
					'asset_splice:5',
					'asset_splice:6',
					'asset_splice:3',
					'COMMITMENT_SIGNED',
					'TX_ABORT'
				];
				for (const side of [I, A]) {
					const names = sentNames(p, side, mark);
					const tail = names.slice(names.indexOf('asset_splice:4'));
					const collapsed = tail.filter(
						(n, k) => !(k > 0 && n === tail[k - 1] && n.startsWith('asset_'))
					);
					expect(
						collapsed.filter(
							(n) => !(CONSTRUCTION_NAMES as readonly string[]).includes(n)
						),
						'side ' + side + ' after its layout_ack'
					).to.deep.equal(skeleton);
					const first = collapsed.findIndex((n) =>
						(CONSTRUCTION_NAMES as readonly string[]).includes(n)
					);
					expect(first, 'construction after final_ack').to.be.greaterThan(
						collapsed.indexOf('asset_splice:5')
					);
					expect(
						collapsed.lastIndexOf('TX_COMPLETE'),
						'tx_complete before the checkpoint'
					).to.be.lessThan(collapsed.indexOf('asset_splice:6'));
					for (const bad of [
						'TX_SIGNATURES',
						'SPLICE_LOCKED',
						'ERROR',
						'WARNING'
					])
						expect(names, 'side ' + side).to.not.include(bad);
					const signed = decodeCommitmentSignedMessage(
						findSent(p, side, 'COMMITMENT_SIGNED', mark)!.payload
					);
					expect(
						hex(signed.fundingTxid!),
						'commitment_signed names the candidate'
					).to.equal(hex(candidateHash(c.fundings[side]!)));
				}
				const turns = p.link.sent.slice(mark).filter(isConstruction);
				expect(
					turns.map((m) => m.from),
					'turns alternate from the initiator'
				).to.deep.equal(turns.map((_m, k) => (k % 2 === 0 ? I : A)));
				expect(
					turns.slice(-2).map((m) => m.name),
					'the last two are tx_complete'
				).to.deep.equal(['TX_COMPLETE', 'TX_COMPLETE']);
				const fence = findSent(p, I, 'TX_ABORT', mark)!;
				expect(abortText(fence)).to.equal(FENCE);
				expect(findSent(p, A, 'TX_ABORT', mark)!.payload).to.deep.equal(
					fence.payload
				);
				expect(p.errors).to.deep.equal([[], []]);
			});
	});

	describe('Ours first, checked first (A4)', () => {
		const I = 0 as const;
		const A = 1 as const;
		const rows: {
			row: string;
			ours: 0 | 1;
			hold: (m: IWireMessage) => boolean;
			/** What the side has sent of the step's own objects (ours first). */
			before?: string;
			done: (p: IConversionPair, mark: number) => boolean;
		}[] = [
			{
				row: '1, consent after both layout_acks',
				ours: A,
				// The held object's sender's later consent is held too, as an
				// ordered connection would deliver it after the layout_ack.
				hold: (m) =>
					m.from === I &&
					(m.name === 'asset_splice:4' || m.name === 'asset_splice_consent'),
				done: (p, mark) =>
					sentNames(p, A, mark).includes('asset_splice_consent')
			},
			{
				row: '2, authorization after both consents',
				ours: A,
				hold: (m) => m.from === I && m.name === 'asset_splice_consent',
				before: 'asset_splice_consent',
				done: (p, mark) => sentNames(p, A, mark).includes('asset_splice:1')
			},
			{
				row: '3, final_ack after both authorizations',
				ours: A,
				hold: (m) => m.from === I && m.name === 'asset_splice:1',
				before: 'asset_splice:1',
				done: (p, mark) => sentNames(p, A, mark).includes('asset_splice:5')
			},
			{
				row: "4, the first construction turn after the peer's final_ack",
				ours: I,
				hold: (m) => m.from === A && m.name === 'asset_splice:5',
				before: 'asset_splice:5',
				done: (p, mark) =>
					p.link.sent.slice(mark).some((m) => m.from === I && isConstruction(m))
			},
			{
				row: "5, the checkpoint after the peer's tx_complete",
				ours: I,
				hold: (m) => m.from === A && m.name === 'TX_COMPLETE',
				done: (p, mark) => sentNames(p, I, mark).includes('asset_splice:6')
			},
			{
				row: "6, the exit share after the peer's checkpoint",
				ours: A,
				hold: (m) => m.from === I && m.name === 'asset_splice:6',
				before: 'asset_splice:6',
				done: (p, mark) => sentNames(p, A, mark).includes('asset_splice:3')
			},
			{
				row: '7, commitment_signed after both exit shares and the verify',
				ours: A,
				// I's commitment_signed is held too: it follows I's exit share
				// on an ordered connection.
				hold: (m) =>
					m.from === I &&
					(m.name === 'asset_splice:3' || m.name === 'COMMITMENT_SIGNED'),
				before: 'asset_splice:3',
				done: (p, mark) => sentNames(p, A, mark).includes('COMMITMENT_SIGNED')
			},
			{
				row: "8, the retain after the peer's commitment_signed",
				ours: A,
				// I's fence is held too: it follows I's commitment_signed on an
				// ordered connection.
				hold: (m) =>
					m.from === I &&
					(m.name === 'COMMITMENT_SIGNED' || m.name === 'TX_ABORT'),
				before: 'COMMITMENT_SIGNED',
				done: (p) => p.hosts[A].calls('retainConversionExits').length === 1
			}
		];
		for (const r of rows)
			it(`A4. row ${r.row}: waits for the peer's material and sends its own object first`, async () => {
				const p = await shared('plain');
				const mark = p.link.sent.length;
				p.link.hold(r.hold);
				const start = track(
					startConversion(p.managers[I], p.channelId, { reference: REF })
				);
				agreeOnTerms(p);
				await p.settle();
				expect(p.link.held.length, 'the peer material waits').to.be.greaterThan(
					0
				);
				if (r.before)
					expect(
						sentNames(p, r.ours, mark),
						'ours first: its own object of the step left'
					).to.include(r.before);
				expect(r.done(p, mark), 'not before the peer material').to.equal(false);
				p.link.clearRules();
				p.link.release();
				await p.settle();
				await start.done;
				expect(r.done(p, mark), 'after the peer material').to.equal(true);
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(abandoned(p, 1)).to.deep.equal([FENCE]);
			});
	});

	describe('The candidate views (A5, A6)', () => {
		it('A5. passes signConversionExits the candidate views to an asset that the asset builder gives at N, by role and feerate', async () => {
			const p = await shared('plain');
			const I = 0 as const;
			const c = capture(p);
			const mark = p.link.sent.length;
			await run(p, I);
			for (const i of [0, 1] as const) {
				const views = c.views[i];
				expect(views, 'side ' + i + ' signed').to.not.equal(undefined);
				const f = candidateFacts(p, i, I, mark, c.fundings[i]!.transaction);
				const root = c.fundings[i]!.fundingRoot!;
				const funding = f.funding(root);
				expect(views!.candidate.type).to.equal('asset');
				expect(views!.candidate.funding).to.deep.equal(funding);
				for (const holder of ['local', 'remote'] as const) {
					const expected = buildAssetSpliceCommitment(
						f.record.candidate as never,
						f.candidateTerms as never,
						holder,
						f.points[holder],
						f.N,
						f.balances,
						[],
						funding,
						f.openingRoot ?? Buffer.alloc(0),
						{ fundingRoot: root },
						branchCommitmentType(ASSET_SPLICE_RECOVERY_TYPE_HEX, f.openingRoot)
					);
					const got = views!.candidate[holder];
					expect(got.tx.toHex(), 'side ' + i + ' ' + holder).to.equal(
						expected.tx.toHex()
					);
					expect(got.tx.outs, 'two balances and two anchors').to.have.length(4);
					expect(got.htlcs).to.deep.equal([]);
				}
			}
		});

		for (const key of ['asset1', 'asset0'] as const)
			it(`A6. passes signConversionExits the candidate views to bitcoin that the plain builder gives with the plain target type (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const I = 0 as const;
				const c = capture(p);
				const mark = p.link.sent.length;
				await run(p, I);
				for (const i of [0, 1] as const) {
					const views = c.views[i];
					expect(views, 'side ' + i + ' signed').to.not.equal(undefined);
					const f = candidateFacts(p, i, I, mark, c.fundings[i]!.transaction);
					const funding = f.funding();
					expect(views!.candidate.type).to.equal('plain');
					for (const holder of ['local', 'remote'] as const) {
						const expected = buildFinalCommitmentView(
							f.record.candidate as never,
							f.candidateTerms as never,
							holder,
							f.points[holder],
							f.N,
							f.balances,
							[],
							funding,
							branchCommitmentType(PLAIN_TARGET_TYPE_HEX, f.openingRoot)
						);
						expect(
							views!.candidate[holder].tx.toHex(),
							'side ' + i + ' ' + holder
						).to.equal(expected.tx.toHex());
						expect(views!.candidate[holder].tx.outs).to.have.length(4);
					}
				}
			});
	});

	describe('Nonces and digests (A7, A8)', () => {
		for (const key of ['plain', 'asset1'] as const)
			it(`A7. carries the candidate's commit nonces at N and N+1 and the shared input nonce in each final tx_complete (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const I = 0 as const;
				const c = capture(p);
				const mark = p.link.sent.length;
				await run(p, I);
				for (const i of [0, 1] as const) {
					const last = p.link.sent
						.slice(mark)
						.filter((m) => m.from === i && m.name === 'TX_COMPLETE')
						.pop();
					expect(last, 'side ' + i + ' final tx_complete').to.not.equal(
						undefined
					);
					const msg = decodeTxCompleteMessage(last!.payload, {
						taproot: true
					} as never) as unknown as {
						commitNonces?: { current: Buffer; next: Buffer };
						fundingInputNonce?: Buffer;
					};
					const f = candidateFacts(p, i, I, mark, c.fundings[i]!.transaction);
					const fundingIndex = f.funding(
						c.fundings[i]!.fundingRoot
					).fundingOutputIndex;
					const authority = deviceAuthority(p.stores[i]);
					const newKey = deriveChannelKeys(
						p.roots[i],
						1,
						lastRecord(p.stores[i], p.id).keyIndex
					).fundingPrivkey;
					const context = authority.nonceContext(
						spliceCommitmentNonceContext(p.id, f.frozen.getHash(), fundingIndex)
					);
					const nonce = (n: bigint): string =>
						hex(
							updateVerificationNonce(context, newKey, Number(n), {
								pub: '',
								source: 'splice'
							} as never)
						);
					expect(hex(msg.commitNonces!.current), 'at N').to.equal(nonce(f.N));
					expect(hex(msg.commitNonces!.next), 'at N+1').to.equal(
						nonce(f.N + 1n)
					);
					const parentTx = Transaction.fromHex(
						p.stores[i].loadFinalOpening(p.id)!.fundingTxHex
					);
					const current = p.stores[i].loadFinalChannelType(p.id)!;
					const coin = stubSellerCoin();
					const prevouts = f.frozen.ins.map((input) =>
						input.hash.equals(parentTx.getHash())
							? parentTx.outs[current.funding.outputIndex]
							: coin.outs[0]
					);
					const sharedIndex = f.frozen.ins.findIndex((input) =>
						input.hash.equals(parentTx.getHash())
					);
					const oldKey = deriveChannelKeys(
						p.roots[i],
						1,
						p.stores[i].loadFinalOpeningSession(p.id)!.channelKeyIndex
					).fundingPrivkey;
					const sharedNonce = finalSpliceSharedNonce(
						{
							digest: taprootKeySpendSighash(
								f.frozen,
								sharedIndex,
								prevouts.map((o) => o.script),
								prevouts.map((o) => o.value)
							)
						} as never,
						oldKey,
						authority
					);
					expect(hex(msg.fundingInputNonce!), 'shared input').to.equal(
						hex(sharedNonce)
					);
				}
			});

		for (const key of ['plain', 'asset1'] as const)
			it(`A8. puts 3.2's final digest in each final_ack and 3.3's digest in each checkpoint (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const I = 0 as const;
				const A = 1 as const;
				const c = capture(p);
				const mark = p.link.sent.length;
				await run(p, I);
				const layoutDigest = p.hostLog.find(
					(x) => x.side === I && x.name === 'prepareConversion'
				)!.args[3] as Buffer;
				const terms = storeTerms(p.stores[I], p.id, { reference: REF });
				const args = c.finalizeArgs[I];
				expect(args, 'finalize was called').to.not.equal(undefined);
				const funding = c.fundings[I]!;
				const digest = finalDigestOf({
					layoutDigest,
					targetType: terms.targetType,
					candidateHash: candidateHash(funding),
					fundingRoot: funding.fundingRoot,
					authorizations: [args!.authorizations[0], args!.authorizations[1]],
					proofDigest: funding.proofDigest
				});
				const nonces = [I, A].map(
					(side) =>
						p.link.sent
							.slice(mark)
							.filter((m) => m.from === side && m.name === 'TX_COMPLETE')
							.pop()!.payload
				) as [Buffer, Buffer];
				const checkpoint = checkpointDigestOf(
					digest,
					candidateHash(funding),
					nonces
				);
				for (const side of [I, A]) {
					expect(
						frameDigests(p, side, 'asset_splice:5', mark).map(hex),
						'final_ack of ' + side
					).to.deep.equal([hex(digest)]);
					expect(
						frameDigests(p, side, 'asset_splice:6', mark).map(hex),
						'checkpoint of ' + side
					).to.deep.equal([hex(checkpoint)]);
				}
				const otherType = Buffer.from(terms.targetType, 'hex');
				otherType[otherType.length - 1] ^= 1;
				expect(
					hex(
						finalDigestOf({
							layoutDigest,
							targetType: hex(otherType),
							candidateHash: candidateHash(funding),
							fundingRoot: funding.fundingRoot,
							authorizations: [
								args!.authorizations[0],
								args!.authorizations[1]
							],
							proofDigest: funding.proofDigest
						})
					)
				).to.not.equal(hex(digest));
			});
	});

	describe('Records (A9 to A11)', () => {
		for (const [key, I] of [
			['plain', 0],
			['asset1', 1]
		] as const)
			it(`A9. writes the attempt, conversion-exits, conversion-dropped and the withdrawal in order before each tx_abort (${LABEL[key]}, side ${I} initiating)`, async () => {
				const p = await shared(key);
				const A = (1 - I) as 0 | 1;
				const base = marks(p);
				const at: Record<string, number[]> = {};
				p.link.taps.push((m) => {
					if (m.name === 'TX_ABORT' || m.name === 'COMMITMENT_SIGNED')
						at[m.from + ':' + m.name] = [
							attemptRowCount(p.stores[m.from], p.id) - base.attempts[m.from],
							conversionRowCount(p.stores[m.from], p.id) -
								base.conversions[m.from]
						];
				});
				const retainedAtCall: number[] = [];
				for (const i of [0, 1] as const) {
					const retain = p.hosts[i].retainExits;
					p.hosts[i].retainExits = (ctx, views, exact): unknown => {
						retainedAtCall[i] =
							conversionRowCount(p.stores[i], p.id) - base.conversions[i];
						return retain(ctx, views, exact);
					};
				}
				await run(p, I);
				expect(at, 'attempt and conversion rows when each left').to.deep.equal({
					[`${I}:COMMITMENT_SIGNED`]: [1, 0],
					[`${A}:COMMITMENT_SIGNED`]: [1, 0],
					[`${I}:TX_ABORT`]: [2, 2],
					[`${A}:TX_ABORT`]: [2, 2]
				});
				expect(
					retainedAtCall,
					'no conversion-exits before the host retained'
				).to.deep.equal([0, 0]);
				for (const i of [0, 1] as const) expectEnded(p, i, base, true, FENCE);
			});

		for (const key of ['plain', 'asset1', 'asset0'] as const)
			it(`A10. reaches retainFinalConversionExits once per side with the parent and the candidate at N under the final digest (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const spies = p.stores.map((st) =>
					sinon.spy(st, 'retainFinalConversionExits')
				);
				const mark = p.link.sent.length;
				await run(p, 0);
				for (const i of [0, 1] as const) {
					expect(spies[i].callCount, 'side ' + i).to.equal(1);
					const exits = spies[i].firstCall.args[1];
					const finalAck = frameDigests(p, i, 'asset_splice:5', mark)[0];
					expect(exits.digest).to.equal(hex(finalAck));
					expect(exits.stateNumber).to.equal(
						storeTerms(p.stores[i], p.id).parent.stateNumber
					);
					expect(exits.parent.type).to.equal(p.kind);
					expect(exits.candidate.type).to.equal(
						p.kind === 'plain' ? 'asset' : 'plain'
					);
					if (exits.candidate.type === 'plain')
						expect(() =>
							verifyPlainBranchWitness(
								exits.candidate as Extract<IFinalExitBranch, { type: 'plain' }>
							)
						).to.not.throw();
				}
			});

		for (const key of ['plain', 'asset1'] as const)
			it(`A11. retains branches equal to the host's receipt and the engine's views, under one digest on both sides (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const c = capture(p);
				const spies = p.stores.map((st) =>
					sinon.spy(st, 'retainFinalConversionExits')
				);
				await run(p, 0);
				const digests: string[] = [];
				for (const i of [0, 1] as const) {
					expect(spies[i].callCount, 'side ' + i).to.equal(1);
					const exits = spies[i].firstCall.args[1];
					const receipt = c.receipts[i] as IConversionExitReceipt;
					expect(exits.parent).to.deep.equal(receipt.parent);
					expect(exits.candidate).to.deep.equal(receipt.candidate);
					const views = c.views[i]!;
					expect(exits.candidate.funding).to.deep.equal(
						views.candidate.funding
					);
					expect(exits.parent.funding).to.deep.equal(views.parent.funding);
					digests.push(exits.digest);
				}
				expect(digests[0]).to.equal(digests[1]);
			});
	});

	describe('A host member declines (A12)', () => {
		type Member =
			| 'consent'
			| 'authorize'
			| 'finalize'
			| 'signExits'
			| 'verifyExits'
			| 'retainExits';
		const MEMBERS: [Member, string, unknown][] = [
			['consent', T.consent, Buffer.alloc(63, 1)],
			['authorize', T.authorize, Buffer.alloc(0)],
			['finalize', T.finalize, null],
			['signExits', T.sign, Buffer.alloc(0)],
			['verifyExits', T.verify, null],
			['retainExits', T.retain, null]
		];
		for (const [member, text, wrong] of MEMBERS)
			for (const how of ['a throw', 'a wrong shape', 'no answer'] as const)
				it(`A12. ends with "${text}" when side 0's ${member} gives ${how}, with no conversion-exits`, async () => {
					const p = await shared('plain');
					const base = marks(p);
					const clock =
						how === 'no answer'
							? sinon.useFakeTimers({
									now: Date.now(),
									toFake: ['Date', 'setTimeout', 'clearTimeout']
							  })
							: undefined;
					const answer = (): unknown => {
						if (how === 'a throw') throw new Error('host refused');
						if (how === 'a wrong shape') return wrong;
						return never();
					};
					(p.hosts[0] as unknown as Record<Member, () => unknown>)[member] =
						answer;
					const mark = p.link.sent.length;
					agreeOnTerms(p);
					const start = track(
						startConversion(p.managers[0], p.channelId, { reference: REF })
					);
					await p.settle();
					if (clock) {
						await tick(p, clock, HOST_BOUND_MS + 1000);
						await tick(p, clock, HOST_BOUND_MS + 1000);
						clock.restore();
					}
					await start.done;
					expect(
						p.hosts[0].calls(
							member === 'signExits'
								? 'signConversionExits'
								: member === 'verifyExits'
								? 'verifyConversionExits'
								: member === 'retainExits'
								? 'retainConversionExits'
								: member
						),
						'the member was called'
					).to.have.length(1);
					expect(abortsFrom(p, 0, mark), 'on the wire').to.include(text);
					expect(abandoned(p, 0), 'in abandon').to.deep.equal([text]);
					for (const i of [0, 1] as const) {
						// The declining side retains nothing. Its peer may have
						// retained before the abort reached it (section 1, step 8),
						// and then drops at the end (7.1).
						expect(
							conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
							'side ' + i + ' no conversion-exits'
						).to.deep.equal(
							i !== 0 && p.hosts[i].calls('retainConversionExits').length
								? ['conversion-exits', 'conversion-dropped']
								: []
						);
						expect(
							attemptEvents(p.stores[i], p.id)
								.slice(base.attempts[i])
								.map((e) => e.kind),
							'side ' + i + ' withdrawn'
						).to.deep.equal(['conversion-attempt', 'conversion-withdrawn']);
					}
					expect(quiet(p)).to.deep.equal([false, false]);
				});
	});

	describe("The plan's shape (A13)", () => {
		for (const missing of ['consent', 'authorize', 'finalize'] as const)
			it(`A13. fails with PREPARE before the record when the plan lacks ${missing}, with no layout_ack`, async () => {
				const p = await shared('plain');
				const base = p.stores.map((st) => attemptRowCount(st, p.id));
				const h = p.hosts[0];
				h.prepare = (ctx, proposals, bitcoin, layoutDigest): unknown => {
					const plan = h.planFor(
						ctx,
						proposals,
						bitcoin,
						layoutDigest
					) as unknown as Record<string, unknown>;
					delete plan[missing];
					return plan;
				};
				const mark = p.link.sent.length;
				await run(p, 0);
				expect(abandoned(p, 0), 'side 0').to.deep.equal([R.prepare]);
				expect(attemptRowCount(p.stores[0], p.id), 'no record').to.equal(
					base[0]
				);
				expect(sentNames(p, 0, mark), 'no layout_ack').to.not.include(
					'asset_splice:4'
				);
			});
	});

	describe('Off by one (A14)', () => {
		/** Side 0 initiates; `setup` breaks one thing; the side named ends with `text`. */
		async function offByOne(
			key: Key,
			side: 0 | 1,
			text: string,
			setup: (p: IConversionPair, mark: number) => void,
			middle?: (p: IConversionPair) => Promise<void>
		): Promise<void> {
			const p = await shared(key);
			const base = marks(p);
			const mark = p.link.sent.length;
			setup(p, mark);
			agreeOnTerms(p);
			const start = track(
				startConversion(p.managers[0], p.channelId, { reference: REF })
			);
			await p.settle();
			if (middle) await middle(p);
			await start.done;
			expect(abandoned(p, side), 'side ' + side).to.deep.equal([text]);
			expect(abortsFrom(p, side, mark).length, 'on the wire').to.be.greaterThan(
				0
			);
			for (const i of [0, 1] as const) {
				// The refusing side retains nothing. Its peer may have retained
				// before the abort reached it (section 1, step 8), and then
				// drops at the end (7.1).
				expect(
					conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
					'side ' + i + ' no conversion-exits'
				).to.deep.equal(
					i !== side && p.hosts[i].calls('retainConversionExits').length
						? ['conversion-exits', 'conversion-dropped']
						: []
				);
				expect(
					attemptEvents(p.stores[i], p.id)
						.slice(base.attempts[i])
						.map((e) => e.kind)
				).to.deep.equal(['conversion-attempt', 'conversion-withdrawn']);
			}
		}

		it('A14. refuses a finalize output 1 sat lower', async () => {
			await offByOne('plain', 0, T.frozen, (p) => {
				p.hosts[0].finalize = (facts): unknown =>
					stubFinalize({
						...facts,
						description: {
							...facts.description,
							outputs: facts.description.outputs.map((o) =>
								o.kind === 'funding' ? o : { ...o, valueSats: o.valueSats - 1n }
							)
						}
					});
			});
		});

		for (const [name, phase, text] of [
			['final_ack', 'asset_splice:5', T.finalAck],
			['checkpoint', 'asset_splice:6', T.checkpoint]
		] as const)
			it(`A14. refuses the peer's ${name} one bit off`, async () => {
				await offByOne(
					'plain',
					0,
					text,
					(p) => p.link.hold({ from: 1, name: phase }),
					async (p) => {
						for (const m of p.link.held) m.payload = flipFrameDigest(m);
						p.link.clearRules();
						p.link.release();
						await p.settle();
					}
				);
			});

		it("A14. refuses the receipt's candidate localBalanceMsat 1 msat off", async () => {
			await offByOne('plain', 0, T.receipt, (p) => {
				const h = p.hosts[0];
				h.retainExits = (ctx, views, exact): unknown => {
					const r = stubExitReceipt(h, ctx, views, exact);
					const rec = r.candidate.localRecovery as { localBalanceMsat: string };
					rec.localBalanceMsat = String(BigInt(rec.localBalanceMsat) + 1n);
					return r;
				};
			});
		});

		it('A14. refuses a receipt commitment rebuilt at a balance 1 sat higher', async () => {
			await offByOne('plain', 0, T.receipt, (p) => {
				const h = p.hosts[0];
				h.retainExits = (ctx, views, exact): unknown => {
					const shifted = {
						...views,
						candidate: {
							...views.candidate,
							remote: {
								...views.candidate.remote,
								localBalanceMsat:
									views.candidate.remote.localBalanceMsat + 1000n,
								remoteBalanceMsat:
									views.candidate.remote.remoteBalanceMsat - 1000n
							}
						}
					} as typeof views;
					const record = openingRecordOf(h.store(), ctx.channelId);
					const leaves = stubExitEvidence(h, ctx, views).candidate!.remote;
					const leaf = (l?: {
						script: string;
						leafVersion?: number;
					}): { script: Buffer; leafVersion?: number } | undefined =>
						l && {
							script: Buffer.from(l.script, 'hex'),
							leafVersion: l.leafVersion
						};
					const b = shifted.candidate as Extract<
						typeof shifted.candidate,
						{ type: 'asset' }
					>;
					const rebuilt = buildAssetSpliceCommitment(
						record.candidate as never,
						views.terms,
						'remote',
						Buffer.from(b.remote.point),
						BigInt(ctx.parent.stateNumber),
						{
							localBalanceMsat: b.remote.localBalanceMsat,
							remoteBalanceMsat: b.remote.remoteBalanceMsat
						},
						[],
						b.funding,
						Buffer.alloc(0),
						{
							fundingRoot: b.fundingRoot,
							toLocal: leaf(leaves.toLocal),
							toRemote: leaf(leaves.toRemote)
						},
						branchCommitmentType(ASSET_SPLICE_RECOVERY_TYPE_HEX, undefined)
					).tx;
					return stubExitReceipt(h, ctx, shifted, {
						...exact,
						candidate: { ...exact.candidate, remote: rebuilt }
					});
				};
			});
		});

		const withdrawalCases: [string, (r: IConversionExitReceipt) => void][] = [
			[
				'1 unit off',
				(r): void => {
					const w = r.withdrawals[0] as { units: string };
					w.units = String(BigInt(w.units) - 1n);
				}
			],
			[
				'at the wrong output index',
				(r): void => {
					(r.withdrawals[0] as { outputIndex: number }).outputIndex += 1;
				}
			],
			[
				'missing',
				(r): unknown =>
					(r as unknown as { withdrawals: unknown[] }).withdrawals.pop()
			],
			[
				'extra',
				(r): unknown =>
					(r as unknown as { withdrawals: unknown[] }).withdrawals.push({
						...r.withdrawals[0]
					})
			],
			[
				'with an empty proof',
				(r): void => {
					(r.withdrawals[0] as { proof: string }).proof = '';
				}
			]
		];
		for (const [what, change] of withdrawalCases)
			it(`A14. refuses, to bitcoin, a withdrawal receipt ${what}`, async () => {
				// The buyer is the giver, the opener of the asset pair's opening.
				const p0 = await pairs.asset1();
				const buyer = (roleOf(p0.stores[0], p0.id) === 'opener' ? 0 : 1) as
					| 0
					| 1;
				await offByOne('asset1', buyer, T.withdrawal, (p) => {
					const h = p.hosts[buyer];
					h.retainExits = (ctx, views, exact): unknown => {
						const r = stubExitReceipt(h, ctx, views, exact);
						change(r);
						return r;
					};
				});
			});

		it('A14. refuses, to bitcoin, parent evidence with one proof byte changed', async () => {
			await offByOne('asset1', 0, T.parentProofs, (p) => {
				const h = p.hosts[0];
				h.verifyExits = (ctx, views): unknown => {
					const e = stubExitEvidence(h, ctx, views);
					const proofs = e.parent!.local.proofs;
					e.parent!.local.proofs =
						(proofs[0] === '0' ? '1' : '0') + proofs.slice(1);
					return e;
				};
			});
		});

		it("A14. refuses the peer's commitment_signed with one partial-signature byte changed", async () => {
			const p = await shared('plain');
			const base = marks(p);
			p.link.hold({ from: 1, name: 'COMMITMENT_SIGNED' });
			const start = await run(p, 0);
			void start;
			expect(p.link.held, 'the peer commitment_signed waits').to.have.length(1);
			const m = p.link.held[0];
			const payload = Buffer.from(m.payload);
			payload[payload.length - 10] ^= 1;
			m.payload = payload;
			p.link.clearRules();
			p.link.release();
			await p.settle();
			const told = abandoned(p, 0);
			expect(told, 'side 0 ends').to.have.length(1);
			expect(told[0]).to.not.equal(FENCE);
			// Side 0 retains nothing. Side 1 took side 0's commitment_signed
			// before the abort and retained (section 1, step 8), then drops.
			for (const i of [0, 1] as const)
				expect(
					conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
					'side ' + i
				).to.deep.equal(
					i === 1 && p.hosts[1].calls('retainConversionExits').length
						? ['conversion-exits', 'conversion-dropped']
						: []
				);
		});
	});

	describe('Withdrawal receipts (A15)', () => {
		it('A15. returns, to bitcoin, one receipt per withdrawal the buyer owns and none for the seller, and pins views.withdrawals', async () => {
			const p = await shared('asset1');
			const c = capture(p);
			await run(p, 0);
			const buyer = (roleOf(p.stores[0], p.id) === 'opener' ? 0 : 1) as 0 | 1;
			const seller = (1 - buyer) as 0 | 1;
			for (const i of [0, 1] as const) {
				const views = c.views[i];
				expect(views, 'side ' + i + ' signed').to.not.equal(undefined);
				const frozen = Transaction.fromBuffer(c.fundings[i]!.transaction);
				const terms = storeTerms(p.stores[i], p.id);
				const issuance = terms.units.issuances[0];
				const withdrawal = frozen.outs.findIndex(
					(o) => o.value === Number(STUB_WITHDRAWAL_SATS)
				);
				expect(
					views!.withdrawals!.map((w) => ({
						assetId: w.assetId,
						outputIndex: w.outputIndex,
						owner: w.owner
					})),
					'side ' + i
				).to.deep.equal(
					views!.withdrawals!.map(() => ({
						assetId: issuance.assetId,
						outputIndex: withdrawal,
						owner: i === buyer ? 'local' : 'remote'
					}))
				);
				expect(
					views!.withdrawals!.reduce((a, w) => a + w.units, 0n),
					'every unit'
				).to.equal(BigInt(issuance.amount));
			}
			expect(c.receipts[buyer]!.withdrawals.length).to.equal(
				c.views[buyer]!.withdrawals!.length
			);
			expect(c.receipts[seller]!.withdrawals).to.deep.equal([]);
		});
	});

	describe('The fence text (A16)', () => {
		it('A16. sends the 4b fence, and no file under src/ has the old text', async () => {
			const p = await shared('plain');
			const mark = p.link.sent.length;
			await run(p, 0);
			expect(abortsFrom(p, 0, mark)).to.deep.equal([FENCE]);
			expect(filesContaining(SRC_DIR, OLD_FENCE)).to.deep.equal([]);
		});
	});

	describe('The drop (A17 to A19)', () => {
		for (const key of ['plain', 'asset1'] as const)
			it(`A17. leaves the candidate dropped, nothing pending, no conversion funding and the exits as they were (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const exitsBefore = p.stores.map((st) =>
					JSON.stringify(st.loadFinalFundingExits(p.id), (_k, v) =>
						typeof v === 'bigint' ? v.toString() : v
					)
				);
				const c = capture(p);
				await run(p, 0);
				for (const i of [0, 1] as const) {
					const store = p.stores[i];
					const conversions = finalConversionsOf(store, p.id);
					expect(conversions.length, 'side ' + i).to.be.greaterThan(0);
					expect(conversions[conversions.length - 1].dropped).to.equal(true);
					expect(pendingConversionsOf(store, p.id)).to.deep.equal([]);
					const txid = Transaction.fromBuffer(
						c.fundings[i]!.transaction
					).getId();
					expect(
						JSON.stringify(fundingsOf(store, p.id), (_k, v) =>
							typeof v === 'bigint' ? v.toString() : v
						),
						'no funding names the candidate'
					).to.not.include(txid);
					expect(
						JSON.stringify(store.loadFinalFundingExits(p.id), (_k, v) =>
							typeof v === 'bigint' ? v.toString() : v
						)
					).to.equal(exitsBefore[i]);
				}
				expect(quiet(p)).to.deep.equal([false, false]);
				await updateRound(p);
			});

		it('A18. runs a second attempt with identical terms to the fence with a new key and digest', async () => {
			const p = await shared('plain');
			const base = marks(p);
			await run(p, 0);
			await run(p, 0);
			for (const i of [0, 1] as const) {
				const attempts = attemptEvents(p.stores[i], p.id).slice(
					base.attempts[i]
				);
				expect(attempts.map((e) => e.kind)).to.deep.equal([
					'conversion-attempt',
					'conversion-withdrawn',
					'conversion-attempt',
					'conversion-withdrawn'
				]);
				const [a, , b] = attempts as unknown as { keyIndex: number }[];
				expect(b.keyIndex, 'a new key').to.not.equal(a.keyIndex);
				const events = conversionEvents(p.stores[i], p.id).slice(
					base.conversions[i]
				);
				expect(events.map((e) => e.kind)).to.deep.equal([
					'conversion-exits',
					'conversion-dropped',
					'conversion-exits',
					'conversion-dropped'
				]);
				expect(events[2].digest, 'a new digest').to.not.equal(events[0].digest);
				expect(events[1].digest).to.equal(events[0].digest);
				expect(events[3].digest).to.equal(events[2].digest);
			}
		});

		for (const key of ['plain', 'asset1'] as const)
			it(`A19. builds the same claims for the peer's current and a revoked parent commitment after a drop, and counts 2 branch rows (${LABEL[key]})`, async () => {
				const p = await fresh(KIND[key], key === 'asset1' ? { rounds: 1 } : {});
				const store = p.stores[0];
				const revoked =
					p.kind === 'plain'
						? Transaction.fromBuffer(
								store.loadFinalResolutionStates(p.id)!.remote[0].tx
						  )
						: undefined;
				if (p.kind === 'plain') await updateRound(p);
				const N = BigInt(storeTerms(store, p.id).parent.stateNumber);
				const commitments =
					p.kind === 'plain'
						? [
								Transaction.fromBuffer(
									store.loadFinalResolutionStates(p.id)!.remote[0].tx
								),
								revoked!
						  ]
						: [
								Transaction.fromHex(
									enrolledAssetParent(store, p.id, N).remoteCommitment
								),
								Transaction.fromHex(
									openingAssetBranch(store, p.id).remoteCommitment
								)
						  ];
				const claims = (): string[] =>
					commitments.map((tx) =>
						claimBytes(
							finalChannelOutputClaims(
								{ storage: store, root: p.roots[0] },
								p.channelId,
								tx,
								Buffer.from('0014' + 'cd'.repeat(20), 'hex'),
								1,
								p.dualFunding[0],
								undefined,
								(cid) => store.loadFinalChannelKind(cid)
							)
						)
					);
				const before = claims();
				const rows = branchRowsOf(store, p.id);
				await run(p, 0);
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				expect(branchRowsOf(store, p.id) - rows, 'branch rows').to.equal(2);
				expect(claims()).to.deep.equal(before);
			});
	});

	describe('Restore after a drop (A20)', () => {
		const authority = deviceAuthority;
		it('A20. lets the wallet and a copy taken after the drop restore, refuses a copy taken before the drop, a planted release, an unknown kind and a tampered row, and reads a device-only drop', async () => {
			const p = await fresh('plain');
			const store = p.stores[0];
			let between: Buffer | undefined;
			const retain = store.retainFinalConversionExits.bind(store);
			sinon
				.stub(store, 'retainFinalConversionExits')
				.callsFake((...args: Parameters<typeof retain>) => {
					const out = retain(...args);
					between = walletDb(store).serialize();
					return out;
				});
			await run(p, 0);
			expect(
				conversionKinds(store, p.id),
				'retained and dropped'
			).to.deep.equal(['conversion-exits', 'conversion-dropped']);
			expect(() =>
				refuseRepair(walletDb(store), authority(store), p.id, store)
			).to.not.throw();
			// A serialized WAL database cannot be opened from memory: mark the
			// copy's header as a rollback journal file (bytes 18 and 19).
			const copy = (bytes: Buffer): Database.Database => {
				const b = Buffer.from(bytes);
				b[18] = 1;
				b[19] = 1;
				return new BetterSqlite(b);
			};
			expect(() =>
				refuseRepair(copy(walletDb(store).serialize()), null, p.id, store)
			).to.not.throw();
			expect(between, 'a copy between the two rows').to.not.equal(undefined);
			expect(() => refuseRepair(copy(between!), null, p.id, store)).to.throw(
				R.restore
			);
			// A tampered row: one byte of the drop row's stored bytes.
			const tampered = copy(walletDb(store).serialize());
			const row = tampered
				.prepare(
					"SELECT rowid AS r, record FROM final_lifecycle_log WHERE scope = 'conversion' AND channel_id = ? ORDER BY rowid DESC LIMIT 1"
				)
				.get(p.id) as { r: number; record: string };
			const at = Math.floor(row.record.length / 2);
			const changed =
				row.record.slice(0, at) +
				(row.record[at] === 'a' ? 'b' : 'a') +
				row.record.slice(at + 1);
			tampered
				.prepare('UPDATE final_lifecycle_log SET record = ? WHERE rowid = ?')
				.run(changed, row.r);
			expect(() => refuseRepair(tampered, null, p.id, store)).to.throw(
				R.restore
			);
			// A planted release of the dropped digest, then an unknown kind.
			const digest = conversionEvents(store, p.id)[0].digest;
			plantConversionEvent(store, p.id, {
				kind: 'conversion-released',
				digest
			});
			expect(() =>
				refuseRepair(walletDb(store), authority(store), p.id, store)
			).to.throw(R.restore);
			const q = await fresh('plain');
			await run(q, 0);
			plantConversionEvent(q.stores[0], q.id, {
				kind: 'conversion-other',
				digest
			});
			expect(() =>
				refuseRepair(
					walletDb(q.stores[0]),
					authority(q.stores[0]),
					q.id,
					q.stores[0]
				)
			).to.throw(R.restore);
		});

		it('A20. reads a drop that is only on the device and lets the wallet restore', async () => {
			const p = await fresh('plain');
			const store = p.stores[0];
			await run(p, 0);
			expect(conversionKinds(store, p.id)).to.deep.equal([
				'conversion-exits',
				'conversion-dropped'
			]);
			// The wallet loses its drop row; the device slot keeps it.
			walletDb(store)
				.prepare(
					"DELETE FROM final_lifecycle_log WHERE rowid = (SELECT MAX(rowid) FROM final_lifecycle_log WHERE scope = 'conversion' AND channel_id = ?)"
				)
				.run(p.id);
			expect(conversionRowCount(store, p.id), 'device only').to.equal(1);
			expect(() =>
				refuseRepair(walletDb(store), deviceAuthority(store), p.id, store)
			).to.not.throw();
		});
	});

	describe('The withdrawal writer and the strict reader (A21, A22)', () => {
		it('A21. drops an undropped candidate before the withdrawal, once, and retain and release refuse a dropped digest', async () => {
			const p = await fresh('plain');
			const at = await toPhase(p, 'P7b', 0);
			const A = at.A;
			const store = p.stores[A];
			expect(conversionKinds(store, p.id).slice(-1)).to.deep.equal([
				'conversion-exits'
			]);
			const writer = attemptStorage(store);
			// The record's own sequence: the scope's rows are 1-based.
			const sequence = attemptRowCount(store, p.id);
			const record = lastRecord(store, p.id);
			silenceConversion(p.managers[A]);
			writer.withdrawConversionAttempt(p.id, sequence, record.attempt, FENCE);
			expect(lifecycleKinds(store, p.id).slice(-3)).to.deep.equal([
				'conversion:conversion-exits',
				'conversion:conversion-dropped',
				'conversion-attempt:conversion-withdrawn'
			]);
			writer.withdrawConversionAttempt(p.id, sequence, record.attempt, FENCE);
			expect(
				conversionKinds(store, p.id).filter((k) => k === 'conversion-dropped')
					.length
			).to.equal(
				conversionKinds(store, p.id).filter((k) => k === 'conversion-exits')
					.length
			);
			const exits = conversionEvents(store, p.id)
				.filter((e) => e.kind === 'conversion-exits')
				.pop()!;
			const { kind: _kind, ...fields } = exits;
			expect(() =>
				store.retainFinalConversionExits(p.id, fields as never, p.roots[A])
			).to.throw(T.dropped);
			expect(() =>
				store.releaseFinalConversionExits(p.id, exits.digest)
			).to.throw(T.dropped);
		});

		it('A21. refuses to drop a released candidate and writes nothing', async () => {
			const p = await fresh('plain');
			const at = await toPhase(p, 'P7b', 0);
			const store = p.stores[at.A];
			const exits = conversionEvents(store, p.id).pop()!;
			expect(exits.kind).to.equal('conversion-exits');
			store.releaseFinalConversionExits(p.id, exits.digest);
			const rows = lastRowid(store);
			silenceConversion(p.managers[at.A]);
			expect(() =>
				attemptStorage(store).withdrawConversionAttempt(
					p.id,
					attemptRowCount(store, p.id),
					lastRecord(store, p.id).attempt,
					FENCE
				)
			).to.throw(T.releasedDrop);
			expect(lastRowid(store), 'nothing written').to.equal(rows);
		});

		const plants: [
			string,
			(e: Record<string, unknown>) => Record<string, unknown>[]
		][] = [
			[
				'a drop with an extra field',
				(e): Record<string, unknown>[] => [
					{ kind: 'conversion-dropped', digest: e.digest, extra: 1 }
				]
			],
			[
				'a short digest',
				(e): Record<string, unknown>[] => [
					{ kind: 'conversion-dropped', digest: String(e.digest).slice(2) }
				]
			],
			[
				'a digest never retained',
				(): Record<string, unknown>[] => [
					{ kind: 'conversion-dropped', digest: 'ab'.repeat(32) }
				]
			],
			[
				'a second drop',
				(e): Record<string, unknown>[] => [
					{ kind: 'conversion-dropped', digest: e.digest }
				]
			],
			[
				'a drop of a released digest',
				(e): Record<string, unknown>[] => [
					{ ...e, digest: 'cd'.repeat(32) },
					{ kind: 'conversion-released', digest: 'cd'.repeat(32) },
					{ kind: 'conversion-dropped', digest: 'cd'.repeat(32) }
				]
			]
		];
		for (const [what, events] of plants)
			it(`A22. refuses ${what} with "${R.invalidExits}"`, async () => {
				const p = await fresh('plain');
				await run(p, 0);
				const store = p.stores[0];
				const exits = conversionEvents(store, p.id).find(
					(e) => e.kind === 'conversion-exits'
				);
				expect(exits, 'retained').to.not.equal(undefined);
				expect(() => pendingConversionsOf(store, p.id)).to.not.throw();
				for (const e of events(exits!)) plantConversionEvent(store, p.id, e);
				expect(() => pendingConversionsOf(store, p.id)).to.throw(
					R.invalidExits
				);
			});
	});

	describe('Nothing else (A23, A24)', () => {
		for (const key of ['plain', 'asset1'] as const)
			it(`A23. changes no lifecycle scope but conversion-attempt and conversion, and reserves no wallet input (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const before = p.stores.map((st) => scopeCounts(st, p.id));
				const base = marks(p);
				await run(p, 0);
				for (const i of [0, 1] as const) {
					const after = scopeCounts(p.stores[i], p.id);
					const changed = Object.keys({ ...before[i], ...after }).filter(
						(k) => (before[i][k] ?? 0) !== (after[k] ?? 0)
					);
					expect(changed.sort(), 'side ' + i).to.deep.equal([
						'conversion',
						'conversion-attempt'
					]);
					expect(
						conversionKinds(p.stores[i], p.id).slice(base.conversions[i])
					).to.deep.equal(['conversion-exits', 'conversion-dropped']);
				}
			});

		for (const key of ['plain', 'asset1'] as const)
			it(`A24. sends no tx_signatures, asks no funding signature, broadcasts nothing and claims no shared input (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const broadcasts: unknown[] = [];
				const listeners = p.managers.map((m) => {
					const fn = (tx: unknown): number => broadcasts.push(tx);
					m.on('broadcast:tx', fn);
					return fn;
				});
				const mark = p.link.sent.length;
				const base = marks(p);
				try {
					await run(p, 0);
				} finally {
					p.managers.forEach((m, i) => m.off('broadcast:tx', listeners[i]));
				}
				for (const i of [0, 1] as const)
					expect(
						conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
						'side ' + i + ' signed and retained'
					).to.deep.equal(['conversion-exits', 'conversion-dropped']);
				expect(
					p.link.sent.slice(mark).filter((m) => m.name === 'TX_SIGNATURES')
				).to.deep.equal([]);
				expect(p.unexpected.filter((n) => /Funding/.test(n))).to.deep.equal([]);
				expect(broadcasts).to.deep.equal([]);
				for (const st of p.stores) {
					const signer = (
						deviceAuthority(st) as unknown as { db?: Database.Database }
					).db;
					if (!signer) continue;
					const tables = signer
						.prepare("SELECT name FROM sqlite_master WHERE type='table'")
						.all() as { name: string }[];
					for (const { name } of tables) {
						const rows = signer.prepare(`SELECT * FROM "${name}"`).all();
						expect(JSON.stringify(rows), name).to.not.include(
							'final-splice/shared-input'
						);
					}
				}
			});
	});

	describe('Routing (A25)', () => {
		it("A25. takes the candidate's commitment_signed in securing without an abort", async () => {
			const p = await shared('plain');
			const at = await toPhase(p, 'P6', 0);
			await at.release();
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			expect(abandoned(p, 1)).to.deep.equal([FENCE]);
		});

		for (const phase of ['P5', 'P7b'] as const)
			it(`A25. aborts with PEER_UPDATED on a commitment_signed naming the parent's funding at ${phase}, with the withdrawal${
				phase === 'P7b' ? ' and the drop' : ''
			} on disk before delivery`, async () => {
				const p = await shared('plain');
				const base = marks(p);
				const at = await toPhase(p, phase, 0);
				const A = at.A;
				const parentTxid = Buffer.from(p.fundingTxid, 'hex').reverse();
				const m = p.managers[A] as unknown as {
					finalTransport: {
						queue(peer: string, id: string, msg: unknown): void;
					};
				};
				const seen: number[][] = [];
				sinon
					.stub(m.finalTransport, 'queue')
					.callsFake((_peer: string, _id: string, msg: unknown) => {
						if (
							(msg as { type: number }).type === MessageType.COMMITMENT_SIGNED
						)
							seen.push([
								attemptRowCount(p.stores[A], p.id) - base.attempts[A],
								conversionRowCount(p.stores[A], p.id) - base.conversions[A]
							]);
					});
				p.managers[A].handleMessage(
					p.nodeIds[at.I],
					MessageType.COMMITMENT_SIGNED,
					forgedCommitmentSigned(p.channelId, parentTxid)
				);
				await p.settle();
				// At P7b the acceptor's tx_abort ends at the initiator's held fence.
				if (phase === 'P7b') await at.release();
				expect(abandoned(p, A), 'side ' + A).to.deep.equal([R.peerUpdated]);
				expect(seen, 'rows at delivery').to.deep.equal([
					[2, phase === 'P7b' ? 2 : 0]
				]);
			});

		it('A25. routes consent and signing frames of another attempt id to the asset splice transport', async () => {
			const p = await shared('plain');
			const at = await toPhase(p, 'P2', 0);
			const splice = (
				p.managers[at.A] as unknown as {
					assetSplice: {
						custom(peer: string, subtype: number, raw: Buffer): void;
					};
				}
			).assetSplice;
			const got = sinon.spy(splice, 'custom');
			const other = randomBytes(32);
			p.managers[at.A].handleAssetOpenFrame(
				p.nodeIds[at.I],
				BeignetCustomSubtype.ASSET_SPLICE_CONSENT,
				encodeAssetOpenConsent({
					attempt: other,
					digest: randomBytes(32),
					signature: randomBytes(64)
				} as never)
			);
			p.managers[at.A].handleAssetOpenFrame(
				p.nodeIds[at.I],
				BeignetCustomSubtype.ASSET_SPLICE,
				rawFrame({
					phase: 3,
					attempt: other,
					digest: randomBytes(32),
					total: 4,
					offset: 0,
					bytes: randomBytes(4)
				})
			);
			await p.settle();
			expect(got.callCount, 'both reached the asset splice transport').to.equal(
				2
			);
			expect(attemptOf(p.managers[at.A], p.id)?.state).to.equal('agreed');
			await at.release();
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		});
	});

	describe('Quiet holds through signing (A26)', () => {
		const plainOps = async (
			p: IConversionPair,
			i: 0 | 1
		): Promise<Record<string, string>> => {
			const m = p.managers[i];
			return {
				add: await refusal(() =>
					m.addHtlc(
						p.channelId,
						1_000_000n,
						sha256(randomBytes(32)),
						PAIR_HEIGHT + 100,
						Buffer.alloc(1366)
					)
				),
				fee: await refusal(() => m.updateChannelFee(p.channelId, 555)),
				splice: await refusal(() =>
					m.startFinalSplice(p.channelId, {
						localDelta: '-10000',
						feeBudget: '2000',
						feerate: 1000,
						locktime: PAIR_HEIGHT,
						inputs: [],
						outputs: []
					} as unknown as Parameters<ChannelManager['startFinalSplice']>[1])
				)
			};
		};
		const assetOps = async (
			p: IConversionPair,
			i: 0 | 1
		): Promise<Record<string, string>> => {
			const m = p.managers[i];
			// Only the original opener may change an asset parent's fee; the
			// other side's fee change is refused by that rule first.
			const opener = roleOf(p.stores[i], p.id) === 'opener';
			return {
				...(opener && {
					fee: await refusal(() =>
						m.startAssetSpliceUpdate(p.channelId, [
							{ kind: 'fee', feeratePerKw: 1500 }
						])
					)
				}),
				splice: await refusal(() =>
					m.startAssetSplice(p.channelId, {
						fundingFeeratePerkw: 1000,
						minimumDepth: 3
					} as never)
				)
			};
		};
		for (const [key, phase] of [
			['plain', 'P1'],
			['plain', 'P4'],
			['plain', 'P6'],
			['plain', 'P7b'],
			['asset1', 'P1'],
			['asset1', 'P4'],
			['asset1', 'P6'],
			['asset1', 'P7b']
		] as const)
			it(`A26. (proposed) refuses local updates and splice starts with the held text from the quiet check, and a new conversion with the held text, at ${phase} (${LABEL[key]})`, async () => {
				const p = await shared(key);
				const at = await toPhase(p, phase, 0);
				for (const m of p.managers)
					(
						conversionTransportOf(m) as unknown as { held(id: string): boolean }
					).held = (): boolean => false;
				const sides = phase === 'P7b' ? [at.A] : [0, 1];
				for (const i of sides as (0 | 1)[]) {
					const out =
						p.kind === 'plain' ? await plainOps(p, i) : await assetOps(p, i);
					expect(out, 'side ' + i).to.deep.equal(
						Object.fromEntries(Object.keys(out).map((k) => [k, R.held]))
					);
					const again = track(
						startConversion(p.managers[i], p.channelId, {
							reference: Buffer.alloc(8, 0x77)
						})
					);
					await again.done;
					expect(again.error, 'a new conversion on side ' + i).to.equal(R.held);
				}
				await at.release();
			});
	});

	describe("The candidate's parameters (A27)", () => {
		it("A27. refuses a candidate dust that differs from the session's after the record, with the parameters text", async () => {
			const p = await shared('plain');
			const base = marks(p);
			const store = p.stores[0];
			p.link.taps.push((m) => {
				if (m.from !== 0 || m.name !== 'asset_splice:4') return;
				const load = store.loadFinalOpeningSession.bind(store);
				sinon.stub(store, 'loadFinalOpeningSession').callsFake((id: string) => {
					const session = load(id)!;
					return {
						...session,
						terms: {
							...session.terms,
							localDustLimitSatoshis:
								Number(session.terms.localDustLimitSatoshis) + 1
						}
					} as typeof session;
				});
			});
			const mark = p.link.sent.length;
			await run(p, 0);
			expect(abandoned(p, 0)).to.deep.equal([R.parameters]);
			expect(
				p.link.sent
					.slice(mark)
					.filter(isConstruction)
					.filter((m) => m.from === 0),
				'no construction'
			).to.deep.equal([]);
			expect(attemptRowCount(p.stores[0], p.id) - base.attempts[0]).to.equal(2);
			expect(
				conversionKinds(store, p.id).slice(base.conversions[0])
			).to.deep.equal([]);
		});
	});

	describe('Asset parents with no secured state (A28, A29)', () => {
		it('A28. converts an asset parent at N = 0 and retains the opening branch at 0', async () => {
			const p = await shared('asset0');
			const spies = p.stores.map((st) =>
				sinon.spy(st, 'retainFinalConversionExits')
			);
			await run(p, 0);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
			for (const i of [0, 1] as const) {
				expect(spies[i].callCount, 'side ' + i).to.equal(1);
				const exits = spies[i].firstCall.args[1];
				expect(exits.stateNumber).to.equal('0');
				expect(exits.parent).to.deep.equal(
					openingAssetBranch(p.stores[i], p.id)
				);
			}
		});

		for (const k of [0, 1])
			it(`A29. converts after an adopted asset splice with ${
				k === 0
					? 'no update since (the receipt candidate)'
					: 'one update since (the added member)'
			}`, async () => {
				// k = 1: one update round on the adopted candidate, through the
				// pair (tests-notes.md item 17).
				const spliced = await assetTypePair(s, 0);
				await spliced.p.start();
				await spliced.p.drain();
				await spliced.p.adopt();
				const p = await conversionPair(s, 'asset', {
					existing: {
						id: spliced.id,
						stores: spliced.devices.map((d) => d.store),
						roots: spliced.devices.map((d) => d.root),
						nodeIds: [spliced.bindings[0].nodeId, spliced.bindings[1].nodeId]
					}
				});
				clean(p);
				if (k === 1) await updateRound(p);
				const spies = p.stores.map((st) =>
					sinon.spy(st, 'retainFinalConversionExits')
				);
				await run(p, 0);
				expect(abandoned(p, 0)).to.deep.equal([FENCE]);
				for (const i of [0, 1] as const) {
					expect(spies[i].callCount, 'side ' + i).to.equal(1);
					const exits = spies[i].firstCall.args[1];
					const expected = enrolledAssetParent(
						p.stores[i],
						p.id,
						BigInt(exits.stateNumber)
					);
					expect(exits.parent.fundingTxid).to.equal(expected.fundingTxid);
					expect(exits.parent).to.deep.equal({
						...expected,
						localCommitment: exits.parent.localCommitment,
						remoteCommitment: exits.parent.remoteCommitment
					});
				}
			});
	});

	describe("The peer's commitment_signed (V5: A30 to A32)", () => {
		it("A30. holds the peer's commitment_signed until our verify returned and our own left", async () => {
			const p = await shared('plain');
			const g = gate();
			const h = p.hosts[0];
			const verify = h.verifyExits;
			h.verifyExits = (ctx, views, shares): unknown =>
				g.wait.then(() => verify(ctx, views, shares));
			let retainedWhenOursLeft = -1;
			p.link.taps.push((m) => {
				if (m.from === 0 && m.name === 'COMMITMENT_SIGNED')
					retainedWhenOursLeft = h.calls('retainConversionExits').length;
			});
			const mark = p.link.sent.length;
			const start = await run(p, 0);
			expect(start.error).to.equal(undefined);
			expect(
				p.hosts[1].calls('verifyConversionExits'),
				'side 1 verified and sent its commitment_signed'
			).to.have.length(1);
			expect(sentNames(p, 1, mark)).to.include('COMMITMENT_SIGNED');
			expect(
				h.calls('retainConversionExits'),
				'side 0 holds it'
			).to.have.length(0);
			expect(attemptOf(p.managers[0], p.id)?.state).to.equal('securing');
			g.open();
			await p.settle();
			expect(retainedWhenOursLeft, 'ours left before the accept').to.equal(0);
			expect(abandoned(p, 0)).to.deep.equal([FENCE]);
		});

		it('A31. aborts with UNEXPECTED on a candidate commitment_signed before both exit shares are exchanged', async () => {
			const p = await shared('plain');
			const c = capture(p);
			const at = await toPhase(p, 'P5', 0);
			p.managers[0].handleMessage(
				p.nodeIds[1],
				MessageType.COMMITMENT_SIGNED,
				forgedCommitmentSigned(p.channelId, candidateHash(c.fundings[0]!))
			);
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([R.unexpected]);
			await at.release();
		});

		for (const differing of [false, true])
			it(`A32. ${
				differing
					? 'aborts with UNEXPECTED on a second commitment_signed that differs'
					: 'drops an identical second commitment_signed'
			}`, async () => {
				const p = await shared('plain');
				const g = gate();
				const h = p.hosts[0];
				const retain = h.retainExits;
				h.retainExits = (ctx, views, exact): unknown =>
					g.wait.then(() => retain(ctx, views, exact));
				p.link.hold({ from: 1, name: 'COMMITMENT_SIGNED' });
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				expect(p.link.held, 'the peer commitment_signed waits').to.have.length(
					1
				);
				const copy = Buffer.from(p.link.held[0].payload);
				if (differing) copy[copy.length - 5] ^= 1;
				p.link.clearRules();
				p.link.release();
				p.link.inject(1, MessageType.COMMITMENT_SIGNED, copy);
				await p.settle();
				g.open();
				await p.settle();
				await start.done;
				expect(abandoned(p, 0)).to.deep.equal([
					differing ? R.unexpected : FENCE
				]);
			});
	});

	describe('The guards (V10: A33 to A40)', () => {
		/** Side 0 initiates with `setup` applied; returns side `side`'s end text. */
		async function guarded(
			key: Key,
			setup: (p: IConversionPair) => void,
			side: 0 | 1 = 0
		): Promise<{
			p: IConversionPair;
			text: string;
			mark: number;
			base: ReturnType<typeof marks>;
		}> {
			const p = await shared(key);
			const base = marks(p);
			setup(p);
			const mark = p.link.sent.length;
			await run(p, 0);
			const told = abandoned(p, side);
			expect(told, 'side ' + side + ' ended once').to.have.length(1);
			// The failing side retains nothing. Its peer may have retained before
			// the abort reached it (section 1, step 8), and then drops (7.1).
			for (const i of [0, 1] as const)
				expect(
					conversionKinds(p.stores[i], p.id).slice(base.conversions[i]),
					'side ' + i
				).to.deep.equal(
					i !== side && p.hosts[i].calls('retainConversionExits').length
						? ['conversion-exits', 'conversion-dropped']
						: []
				);
			return { p, text: told[0], mark, base };
		}
		const afterRecord = (
			p: IConversionPair,
			side: 0 | 1,
			act: () => void
		): void => {
			p.link.taps.push((m) => {
				if (m.from === side && m.name === 'asset_splice:4') act();
			});
		};

		for (const [what, stub] of [
			[
				'the key allocation',
				(p: IConversionPair): void =>
					afterRecord(p, 0, () =>
						sinon
							.stub(deviceAuthority(p.stores[0]), 'requireAllocatedChannelKey')
							.throws(new Error('test: key not allocated'))
					)
			],
			[
				'the original device',
				// Installed as finalize is called: the device check serves the
				// parent rechecks too, so an earlier stub ends before finalize.
				(p: IConversionPair): void => {
					const finalize = p.hosts[0].finalize;
					p.hosts[0].finalize = (...args): unknown => {
						sinon
							.stub(p.stores[0], 'requireOpeningAuthority')
							.throws(new Error('test: not the original device'));
						return finalize(...args);
					};
				}
			],
			[
				'the current ledger',
				(p: IConversionPair): void =>
					afterRecord(p, 0, () =>
						sinon
							.stub(
								p.stores[0] as unknown as {
									currentLedgerCommitments(): unknown;
								},
								'currentLedgerCommitments'
							)
							.returns(null)
					)
			]
		] as const)
			it(`A33. (proposed) refuses at the round's constructor when ${what} check fails, before any construction turn`, async () => {
				const { p, text, mark } = await guarded('plain', stub);
				expect(text).to.not.be.oneOf([FENCE, OLD_FENCE]);
				expect(
					p.link.sent.slice(mark).filter(isConstruction),
					'no construction'
				).to.deep.equal([]);
				expect(p.hosts[0].calls('finalize'), 'after finalize').to.have.length(
					1
				);
			});

		it(`A34. refuses a peer exit frame while consents are exchanged with "${T.premature}"`, async () => {
			const p = await shared('plain');
			const at = await toPhase(p, 'P1', 0);
			const attempt = Buffer.from(lastRecord(p.stores[0], p.id).attempt, 'hex');
			p.managers[0].handleAssetOpenFrame(
				p.nodeIds[1],
				BeignetCustomSubtype.ASSET_SPLICE,
				rawFrame({
					phase: 3,
					attempt,
					digest: sha256(Buffer.from('x')),
					total: 1,
					offset: 0,
					bytes: Buffer.from('x')
				})
			);
			await p.settle();
			expect(abandoned(p, 0)).to.deep.equal([T.premature]);
			await at.release();
		});

		for (const differs of [true, false])
			it(`A34. ${
				differs
					? `refuses a second consent that differs with "${T.conflicting}"`
					: 'drops an identical second consent and reaches the fence'
			}`, async () => {
				const p = await shared('plain');
				p.link.hold({ from: 1, name: 'asset_splice_consent' });
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				expect(attemptOf(p.managers[0], p.id)?.state, 'side 0 agreed').to.equal(
					'agreed'
				);
				const held = p.link.held.find((m) => m.name === 'asset_splice_consent');
				expect(held, 'the peer consent waits').to.not.equal(undefined);
				const copy = Buffer.from(held!.payload);
				if (differs) copy[copy.length - 1] ^= 1;
				p.link.clearRules();
				p.link.release();
				p.link.inject(1, BEIGNET_CUSTOM_MESSAGE_TYPE, copy);
				await p.settle();
				await start.done;
				expect(abandoned(p, 0)).to.deep.equal([
					differs ? T.conflicting : FENCE
				]);
			});

		const frozenCases: [
			string,
			Key,
			(f: Record<string, unknown>) => void,
			string
		][] = [
			[
				'a layout digest one bit off',
				'plain',
				(f): void => {
					const d = Buffer.from(f.layoutDigest as Buffer);
					d[0] ^= 1;
					f.layoutDigest = d;
				},
				T.frozen
			],
			[
				'a root of 31 bytes, to an asset',
				'plain',
				(f): void => {
					f.fundingRoot = (f.fundingRoot as Buffer).subarray(1);
				},
				T.frozen
			],
			[
				'empty funding proofs, to an asset',
				'plain',
				(f): void => {
					f.fundingProofs = Buffer.alloc(0);
				},
				T.frozen
			],
			[
				'no root, to an asset',
				'plain',
				(f): void => {
					delete f.fundingRoot;
				},
				T.frozen
			],
			[
				'a root, to bitcoin',
				'asset1',
				(f): void => {
					f.fundingRoot = Buffer.alloc(32, 1);
					f.fundingProofs = Buffer.alloc(1, 1);
				},
				T.frozen
			],
			[
				'a proof digest of 31 bytes',
				'plain',
				(f): void => {
					f.proofDigest = (f.proofDigest as Buffer).subarray(1);
				},
				T.frozen
			],
			[
				'an extra output',
				'plain',
				(f): void => {
					const tx = Transaction.fromBuffer(f.transaction as Buffer);
					tx.addOutput(
						Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 9)]),
						1000
					);
					f.transaction = tx.toBuffer();
				},
				T.frozen
			],
			[
				'a transaction that is not an object field',
				'plain',
				(f): void => {
					f.transaction = 'not bytes';
				},
				T.finalize
			]
		];
		for (const [what, key, change, text] of frozenCases)
			it(`A35. (proposed) refuses a finalize answer with ${what} with "${text}"`, async () => {
				const { text: got } = await guarded(key, (p) => {
					p.hosts[0].finalize = (facts): unknown => {
						const f = stubFinalize(facts) as unknown as Record<string, unknown>;
						change(f);
						return f;
					};
				});
				expect(got).to.equal(text);
			});

		const evidenceCases: [
			string,
			Key,
			(e: {
				parent: unknown;
				candidate: Record<
					string,
					{ proofs: string; toLocal?: { script: string } }
				> | null;
			}) => void
		][] = [
			[
				'plain evidence that is not null',
				'plain',
				(e): void => {
					e.parent = { local: { proofs: 'aa' }, remote: { proofs: 'aa' } };
				}
			],
			[
				'uppercase proofs',
				'plain',
				(e): void => {
					e.candidate!.local.proofs = e.candidate!.local.proofs.toUpperCase();
				}
			],
			[
				'an invalid leaf',
				'plain',
				(e): void => {
					e.candidate!.local.toLocal = { script: 'zz' };
				}
			]
		];
		for (const [what, key, change] of evidenceCases)
			it(`A36. refuses evidence with ${what} with "${T.evidence}"`, async () => {
				const { text } = await guarded(key, (p) => {
					const h = p.hosts[0];
					h.verifyExits = (ctx, views): unknown => {
						const e = stubExitEvidence(h, ctx, views) as never;
						change(e);
						return e;
					};
				});
				expect(text).to.equal(T.evidence);
			});

		const receiptCases: [
			string,
			(r: Record<string, unknown> & IConversionExitReceipt) => void
		][] = [
			[
				'another channel id',
				(r): void => {
					r.channelId = 'ab'.repeat(32);
				}
			],
			[
				'another final digest',
				(r): void => {
					r.finalDigest = 'ab'.repeat(32);
				}
			],
			[
				'another state number',
				(r): void => {
					r.stateNumber = String(BigInt(r.stateNumber) + 1n);
				}
			],
			[
				'another owned output index',
				(r): void => {
					const rec = r.candidate.localRecovery as {
						ownedOutputIndex?: number | null;
					};
					rec.ownedOutputIndex = (rec.ownedOutputIndex ?? 0) + 1;
				}
			]
		];
		for (const [what, change] of receiptCases)
			it(`A37. refuses a receipt with ${what} with "${T.receipt}"`, async () => {
				const { text } = await guarded('plain', (p) => {
					const h = p.hosts[0];
					h.retainExits = (ctx, views, exact): unknown => {
						const r = stubExitReceipt(h, ctx, views, exact) as never;
						change(r);
						return r;
					};
				});
				expect(text).to.equal(T.receipt);
			});

		const unexpected: [string, (p: IConversionPair) => [number, Buffer]][] = [
			[
				'tx_signatures',
				(p): [number, Buffer] => [
					MessageType.TX_SIGNATURES,
					encodeTxSignaturesMessage({
						channelId: p.channelId,
						txid: randomBytes(32),
						witnesses: []
					} as never)
				]
			],
			[
				'tx_remove_input',
				(p): [number, Buffer] => [
					MessageType.TX_REMOVE_INPUT,
					encodeTxRemoveInputMessage({ channelId: p.channelId, serialId: 1n })
				]
			],
			[
				'tx_init_rbf',
				(p): [number, Buffer] => [
					MessageType.TX_INIT_RBF,
					encodeTxInitRbfMessage({
						channelId: p.channelId,
						locktime: PAIR_HEIGHT,
						feerate: 2000
					} as never)
				]
			],
			[
				'a phase 2 frame',
				(p): [number, Buffer] => [
					BEIGNET_CUSTOM_MESSAGE_TYPE,
					encodeCustomMessage(
						BeignetCustomSubtype.ASSET_SPLICE,
						rawFrame({
							phase: 2,
							attempt: Buffer.from(
								lastRecord(p.stores[0], p.id).attempt,
								'hex'
							),
							digest: sha256(Buffer.from('h')),
							total: 1,
							offset: 0,
							bytes: Buffer.from('h')
						})
					)
				]
			]
		];
		for (const [what, make] of unexpected)
			it(`A38. aborts with UNEXPECTED on ${what} in securing`, async () => {
				const p = await shared('plain');
				const at = await toPhase(p, 'P5', 0);
				const [type, payload] = make(p);
				if (type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
					const { subtype, frame } = customPayload(payload);
					p.managers[0].handleAssetOpenFrame(p.nodeIds[1], subtype, frame);
				} else p.managers[0].handleMessage(p.nodeIds[1], type, payload);
				await p.settle();
				expect(abandoned(p, 0)).to.deep.equal([R.unexpected]);
				await at.release();
			});

		it('A39. counts conversionRoots as asset roots in finalSpliceFeeError, so no Eclair quote exception applies', () => {
			const terms = {
				localIsSpliceInitiator: false,
				localDelta: 0n,
				peerDelta: -10_000n,
				localFeeBudget: 0n,
				feerate: 1000
			};
			const weight = 1000;
			const quote = BigInt(Math.floor(((weight - 2) * terms.feerate) / 1000));
			expect(
				finalSpliceFeeError(quote, weight, terms as never, true),
				'the exception'
			).to.equal(null);
			expect(
				finalSpliceFeeError(
					quote,
					weight,
					{
						...terms,
						conversionRoots: { candidate: Buffer.alloc(32, 1) }
					} as never,
					true
				),
				'a conversion takes none'
			).to.not.equal(null);
		});

		it("A40. refuses a construction turn that differs from the frozen transaction with the construction core's text", async () => {
			const p = await shared('plain');
			const at = await toPhase(p, 'P4', 0);
			const c = conversionEvents(p.stores[0], p.id);
			void c;
			p.managers[1].handleMessage(
				p.nodeIds[0],
				MessageType.TX_ADD_OUTPUT,
				encodeTxAddOutputMessage({
					channelId: p.channelId,
					serialId: 1000n,
					amountSats: 5000n,
					scriptPubkey: Buffer.concat([
						Buffer.from([0x51, 0x20]),
						randomBytes(32)
					])
				})
			);
			await p.settle();
			expect(abandoned(p, 1)).to.deep.equal([
				'Unexpected asset splice construction turn or contribution'
			]);
			await at.release();
		});

		it('A40. ends at the terms expiry while signing (parentUnchanged after an await)', async () => {
			const p = await shared('plain');
			const at = await toPhase(p, 'P7a', 0);
			const clock = sinon.useFakeTimers({
				now: 4_000_000_001 * 1000,
				toFake: ['Date']
			});
			try {
				await at.release();
			} finally {
				clock.restore();
			}
			expect(abandoned(p, 0)[0]).to.equal(
				'Asset conversion agreement has expired'
			);
		});

		it('A40. bounds the echo of a tx_abort sent after our commitment_signed at 30 s, not 15 s (V2)', async () => {
			const p = await shared('plain');
			const g = gate();
			const h = p.hosts[0];
			h.retainExits = (): unknown =>
				g.wait.then(() => {
					throw new Error('host refused');
				});
			p.link.drop({ from: 1, name: 'TX_ABORT' });
			const clock = sinon.useFakeTimers({
				now: Date.now(),
				toFake: ['Date', 'setTimeout', 'clearTimeout']
			});
			try {
				agreeOnTerms(p);
				const start = track(
					startConversion(p.managers[0], p.channelId, { reference: REF })
				);
				await p.settle();
				expect(
					h.calls('retainConversionExits'),
					'side 0 retains'
				).to.have.length(1);
				g.open();
				await p.settle();
				expect(abortsFrom(p, 0)).to.include(T.retain);
				await tick(p, clock, 16_000);
				expect(p.recycled[0], 'no disconnect at 15 s').to.deep.equal([]);
				await tick(p, clock, 15_000);
				expect(p.recycled[0].length, 'a disconnect at 30 s').to.be.greaterThan(
					0
				);
				await start.done;
			} finally {
				clock.restore();
			}
		});
	});

	describe('W2. The fence in one read with the commitment_signed', () => {
		it("W2-burst. retains once per side when the initiator's commitment_signed and fence arrive in one turn, and the acceptor echoes after its conversion-exits", async () => {
			const p = await shared('plain');
			const base = marks(p);
			const I = 0 as const;
			const A = 1 as const;
			p.link.hold(
				(m) =>
					m.from === I &&
					(m.name === 'COMMITMENT_SIGNED' || m.name === 'TX_ABORT')
			);
			let exitsAtEcho = -1;
			p.link.taps.push((m) => {
				if (m.from === A && m.name === 'TX_ABORT')
					exitsAtEcho = conversionKinds(p.stores[A], p.id)
						.slice(base.conversions[A])
						.indexOf('conversion-exits');
			});
			agreeOnTerms(p);
			const start = track(
				startConversion(p.managers[I], p.channelId, { reference: REF })
			);
			await p.settle();
			expect(
				p.link.held.map((m) => m.name),
				'held in order'
			).to.deep.equal(['COMMITMENT_SIGNED', 'TX_ABORT']);
			p.link.clearRules();
			p.link.burst(
				(m) =>
					m.from === I &&
					(m.name === 'COMMITMENT_SIGNED' || m.name === 'TX_ABORT')
			);
			p.link.release();
			await p.settle();
			await start.done;
			for (const i of [0, 1] as const) {
				expect(
					p.hosts[i].calls('retainConversionExits'),
					'side ' + i + ' retained once'
				).to.have.length(1);
				expectEnded(p, i, base, true, FENCE);
			}
			expect(exitsAtEcho, 'the echo after conversion-exits').to.equal(0);
		});
	});
});

/** `<scope>:<kind>` of a channel's conversion and attempt rows, in insertion order. */
function lifecycleKinds(store: SqliteStorage, id: string): string[] {
	const attempts = attemptEvents(store, id).map(
		(e) => 'conversion-attempt:' + e.kind
	);
	const conversions = conversionEvents(store, id).map(
		(e) => 'conversion:' + e.kind
	);
	const order = (
		walletDb(store)
			.prepare(
				"SELECT scope FROM final_lifecycle_log WHERE channel_id = ? AND scope IN ('conversion', 'conversion-attempt') ORDER BY rowid"
			)
			.all(id) as { scope: string }[]
	).map((r) => r.scope);
	const out: string[] = [];
	let a = 0;
	let c = 0;
	for (const scope of order)
		out.push(scope === 'conversion' ? conversions[c++] : attempts[a++]);
	return out;
}

void hex;
void frameOf;
void parseFrame;
void assetSpliceCustom;
void never;
