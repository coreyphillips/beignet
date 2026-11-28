/**
 * #2151 Step 4b, amendment v2.2 (X5, X6 and X15): the guards the wire
 * cannot reach. The round's constructor refuses a derived key that differs
 * (2.6), the round refuses a construction whose transaction differs from
 * the agreed candidate (3.1, through the construction seam), and the
 * tombstone owns only its own candidate's commitment_signed (W1).
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
import { MessageType } from '../../src/lightning/message/types';
import { scratch } from './helpers/channel-type-pairs';
import {
	attemptOf,
	sharedPair,
	type IConversionPair
} from './helpers/conversion-managers';
import { forgedCommitmentSigned, toPhase } from './helpers/conversion-signing';

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

	it("X15. the tombstone owns only its candidate's commitment_signed", () => {
		const transport = new AssetConversionTransport(undefined, undefined, {
			localFeatures: () => undefined,
			remoteFeatures: () => undefined,
			connected: () => false,
			hasDepth: () => false,
			busy: () => false,
			settled: async () => undefined,
			height: () => 0,
			send: () => undefined,
			disconnect: () => undefined,
			report: () => undefined
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
});
