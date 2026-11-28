/**
 * #2151 Step 4b, amendment v2.2 (X5, X6 and X15): the guards the wire
 * cannot reach. The round's constructor refuses a derived key that differs
 * (2.6), the round refuses a construction whose transaction differs from
 * the agreed candidate (3.1, through the construction seam), and the
 * tombstone owns only its own candidate's commitment_signed (W1). The last
 * test pins W6's tolerant read, which no test reached.
 */
import { expect } from 'chai';
import sinon from 'sinon';
import { Transaction } from 'bitcoinjs-lib';
import {
	ConversionSignatureRound,
	CONVERSION_ROUND_TEXTS,
	type IConversionRoundFacts
} from '../../src/lightning/channel/asset-conversion-signature-round';
import { AssetConversionTransport } from '../../src/lightning/channel/asset-conversion-transport';
import type { SpliceConstructionCore } from '../../src/lightning/channel/asset-splice-construction';
import { buildFinalSpliceCandidate } from '../../src/lightning/channel/final-splice-candidate';
import { MessageType } from '../../src/lightning/message/types';
import { encodeAssetOpenConsent } from '../../src/lightning/message/asset-open';
import { BeignetCustomSubtype } from '../../src/lightning/message/custom';
import { scratch } from './helpers/channel-type-pairs';
import { finalBranchReaders } from '../../src/lightning/storage/final-branch-readers';
import { deviceAuthority } from './helpers/channel-type-record';
import { attemptEvents } from './helpers/conversion-attempts';
import {
	abandoned,
	agreeOnTerms,
	attemptOf,
	sharedPair,
	startConversion,
	track,
	type IConversionPair
} from './helpers/conversion-managers';
import {
	conversionEvents,
	forgedCommitmentSigned,
	fundingsOf,
	pendingConversionsOf,
	plantConversionEvent,
	refuseRepair,
	toPhase,
	walletDb
} from './helpers/conversion-signing';

interface IRoundView {
	f: IConversionRoundFacts;
}

describe('Asset conversion round guards (#2151 step 4b, X5, X6 and X15)', function () {
	this.timeout(240000);
	const s = scratch('conversion-round-guards-');
	const pair = sharedPair(s, 'plain');
	let p: IConversionPair;
	let facts: IConversionRoundFacts;
	let round: ConversionSignatureRound;

	before(async () => {
		p = await pair();
		// The initiator holds a frozen candidate while the acceptor's turns wait.
		await toPhase(p, 'P4', 0);
		const a = attemptOf(p.managers[0], p.id) as unknown as {
			round: ConversionSignatureRound;
		};
		round = a.round;
		facts = (round as unknown as IRoundView).f;
	});
	afterEach(() => sinon.restore());
	after(async () => {
		p.link.clearRules();
		p.link.held.splice(0);
		p.disconnect();
		s.release();
	});

	const build = (f: IConversionRoundFacts): ConversionSignatureRound =>
		new ConversionSignatureRound(p.stores[0], p.roots[0], f);

	it('X5. builds a round from the attempt facts as they are', () => {
		expect(() => build(facts)).to.not.throw();
	});

	it("X5. refuses a candidate key that is not the allocated key's derivation", () => {
		const terms = facts.verified.terms;
		expect(() =>
			build({
				...facts,
				verified: {
					...facts.verified,
					terms: { ...terms, newLocalKey: Buffer.from(terms.newPeerKey) }
				}
			})
		).to.throw(CONVERSION_ROUND_TEXTS.key);
	});

	it("X5. refuses a parent key that is not the parent funding key's derivation", () => {
		const terms = facts.verified.terms;
		expect(() =>
			build({
				...facts,
				verified: {
					...facts.verified,
					terms: { ...terms, oldLocalKey: Buffer.from(terms.oldPeerKey) }
				}
			})
		).to.throw(CONVERSION_ROUND_TEXTS.key);
	});

	it("X5. refuses an opening whose own funding key is not the device's derivation", () => {
		const store = p.stores[0];
		const load = store.loadFinalDaemonOpening.bind(store);
		sinon.stub(store, 'loadFinalDaemonOpening').callsFake((id: string) => {
			const opening = load(id)!;
			return {
				...opening,
				candidate: {
					...opening.candidate,
					localFundingPubkey: opening.candidate.remoteFundingPubkey
				}
			} as typeof opening;
		});
		expect(() => build(facts)).to.throw(CONVERSION_ROUND_TEXTS.key);
	});

	it("X5. refuses a parent funding whose recorded key is not its index's derivation", () => {
		const terms = facts.verified.terms;
		const other = Buffer.from(terms.oldPeerKey);
		expect(() =>
			build({
				...facts,
				parent: {
					...facts.parent,
					funding: {
						...facts.parent.funding,
						localFundingPubkey: other.toString('hex')
					}
				},
				verified: {
					...facts.verified,
					terms: { ...terms, oldLocalKey: other }
				}
			})
		).to.throw(CONVERSION_ROUND_TEXTS.key);
	});

	it("4.2. refuses a layout whose candidate dust differs from the session's", () => {
		const [d0, d1] = facts.layout.candidateDustSats;
		expect(() =>
			build({
				...facts,
				layout: { ...facts.layout, candidateDustSats: [d0 + 1n, d1] }
			})
		).to.throw("Asset conversion channel parameters differ from the channel's");
	});

	it('X6. refuses a construction whose transaction differs from the agreed candidate', () => {
		const other = Transaction.fromBuffer(
			facts.verified.candidate.tx.toBuffer()
		);
		other.locktime ^= 1;
		sinon.stub(round, 'construction').returns({
			agreement: () => ({ candidate: { tx: other } })
		} as unknown as SpliceConstructionCore);
		expect(() => round.agreement()).to.throw(
			CONVERSION_ROUND_TEXTS.interactive
		);
	});

	it('2.5. refuses conversionRoots with two roots, with asset roots, or a root that is not 32 bytes', () => {
		const terms = facts.verified.terms;
		const tx = facts.verified.candidate.tx;
		const inputs = facts.layout.inputs.map((i) => ({
			...i,
			prevTxid: Buffer.from(i.prevTxid),
			prevTx: i.prevTx && Buffer.from(i.prevTx)
		}));
		const outputs = facts.layout.outputs.map((o, i) => ({
			serialId: o.serialId,
			amountSats: o.amountSats,
			scriptPubkey: Buffer.from(tx.outs[i].script)
		}));
		const root = terms.conversionRoots!.candidate!;
		expect(
			buildFinalSpliceCandidate(terms, inputs, outputs).tx.toHex(),
			'the frozen candidate'
		).to.equal(tx.toHex());
		for (const conversionRoots of [
			{ parent: Buffer.alloc(32, 1), candidate: root },
			{},
			{ candidate: root.subarray(1) }
		])
			expect(() =>
				buildFinalSpliceCandidate(
					{ ...terms, conversionRoots },
					inputs,
					outputs
				)
			).to.throw('Invalid final splice terms');
		expect(() =>
			buildFinalSpliceCandidate(
				{
					...terms,
					assetFundingRoots: { parent: Buffer.alloc(32, 1), candidate: root }
				},
				inputs,
				outputs
			)
		).to.throw('Invalid final splice terms');
	});

	it("X15. the tombstone owns only its candidate's commitment_signed", () => {
		const transport = new AssetConversionTransport(undefined, undefined, {
			localFeatures: (): undefined => undefined,
			remoteFeatures: (): undefined => undefined,
			connected: (): boolean => false,
			hasDepth: (): boolean => false,
			busy: (): boolean => false,
			settled: async (): Promise<void> => undefined,
			height: (): number => 0,
			send: (): void => undefined,
			disconnect: (): void => undefined,
			report: (): void => undefined
		});
		const id = Buffer.alloc(32, 0x11);
		const candidate = Buffer.alloc(32, 0x22);
		const peer = '02' + '33'.repeat(32);
		(
			transport as unknown as {
				tombstones: Map<string, { peer: string; candidate: Buffer }>;
			}
		).tombstones.set(id.toString('hex'), { peer, candidate });
		const handle = (txid: Buffer, from = peer): boolean =>
			transport.handle(
				from,
				MessageType.COMMITMENT_SIGNED,
				forgedCommitmentSigned(id, txid)
			);
		// An asset splice's candidate, or the parent's funding: not owned.
		expect(handle(Buffer.alloc(32, 0x44)), 'another funding').to.equal(false);
		expect(handle(candidate, '02' + '55'.repeat(32)), 'another peer').to.equal(
			false
		);
		expect(handle(candidate), 'the tombstoned candidate').to.equal(true);
		transport.disconnected(peer);
		expect(handle(candidate), 'after a disconnect').to.equal(false);
	});

	it('2.1. refuses a consent whose digest is not the agreement', async () => {
		// Last in this block: it ends the attempt the facts came from.
		const a = attemptOf(p.managers[0], p.id) as unknown as { attempt: Buffer };
		p.managers[0].handleAssetOpenFrame(
			p.nodeIds[1],
			BeignetCustomSubtype.ASSET_SPLICE_CONSENT,
			encodeAssetOpenConsent({
				attempt: a.attempt,
				digest: Buffer.alloc(32, 9),
				signature: Buffer.alloc(64, 1)
			})
		);
		await p.settle();
		expect(abandoned(p, 0)).to.deep.equal(['Invalid asset conversion consent']);
	});
});

describe('The tolerant read of the conversion scope (#2151 step 4b, W6)', function () {
	this.timeout(240000);
	const s = scratch('conversion-tolerant-read-');
	const pair = sharedPair(s, 'plain');
	after(() => s.release());

	it('W6. ignores a malformed scope on the claim and exit paths and refuses it on the conversion paths', async () => {
		const p = await pair();
		agreeOnTerms(p);
		await track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(8, 0x57)
			})
		).done;
		await p.settle();
		const store = p.stores[0];
		const [exits] = conversionEvents(store, p.id);
		expect(exits?.kind, 'retained').to.equal('conversion-exits');
		const fundings = fundingsOf(store, p.id);
		// A second drop of one digest breaks the strict rules (7.2).
		plantConversionEvent(store, p.id, {
			kind: 'conversion-dropped',
			digest: exits.digest
		});
		expect(fundingsOf(store, p.id), 'the claim fundings').to.deep.equal(
			fundings
		);
		expect(
			finalBranchReaders(store)!.finalConversion(p.id, exits.digest),
			'the chain readers see nothing'
		).to.equal(null);
		expect(() => pendingConversionsOf(store, p.id)).to.throw(
			'Invalid conversion exits'
		);
		expect(() =>
			refuseRepair(walletDb(store), deviceAuthority(store), p.id, store)
		).to.throw(
			'Restore of a channel with a pending type conversion is not supported yet'
		);
	});
});

describe('The drop names only the current record (#2151 step 4b, W5)', function () {
	this.timeout(240000);
	const s = scratch('conversion-stale-drop-');
	const pair = sharedPair(s, 'plain');
	after(() => s.release());

	it("W5. a withdrawal at an earlier record's sequence drops no newer candidate", async () => {
		const p = await pair();
		agreeOnTerms(p);
		await track(
			startConversion(p.managers[0], p.channelId, {
				reference: Buffer.alloc(8, 0x58)
			})
		).done;
		await p.settle();
		const store = p.stores[1];
		const first = attemptEvents(store, p.id)[0] as unknown as {
			attempt: string;
		};
		// A second attempt: the acceptor retains and waits for the held fence.
		const at = await toPhase(p, 'P7b', 0);
		const kinds = conversionEvents(store, p.id).map((e) => e.kind);
		expect(kinds.slice(-1), 'the new candidate').to.deep.equal([
			'conversion-exits'
		]);
		finalBranchReaders(store)!.withdrawConversionAttempt(
			p.id,
			1,
			first.attempt,
			'stale'
		);
		expect(
			conversionEvents(store, p.id).map((e) => e.kind),
			'nothing dropped'
		).to.deep.equal(kinds);
		await at.release();
	});
});
