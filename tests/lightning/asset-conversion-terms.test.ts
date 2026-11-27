/**
 * #2151 Step 3a, contract test 2: the conversion terms (section 3).
 *
 * - the canonical form and the digest, pinned by bytes written by hand here;
 * - a host's key order does not change the canonical bytes or the digest;
 * - the canonical form checks structure only (amendment v3.1 item 3): a
 *   missing or extra key, a value of the wrong JSON type, and a Role or
 *   direction outside its union are refused one field at a time, and every
 *   value grammar violation is accepted and digested, since the numbered
 *   checks refuse those;
 * - symmetry: each peer derives the fields it checks from its own store,
 *   naming each side by its role in the opening, and both digests agree.
 *
 * The engine's ordered checks (section 3, 1 to 10) run inside the transport
 * and are tested through two channel managers in the agreement tests.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import type { IAssetConversionTerms } from '../../src/lightning/channel/asset-conversion-terms';
import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from '../../src/lightning/features/asset-opening';
import type { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	assetTypePair,
	plainTypePair,
	scratch,
	type Scratch
} from './helpers/channel-type-pairs';
import { conversionTerms } from './helpers/conversion-modules';
import {
	copyTerms,
	GRAMMAR_CASES,
	PLAIN_TARGET_TYPE_HEX,
	SAMPLE_ASSET_A,
	SAMPLE_EXPIRES_AT,
	SAMPLE_PARENT_TXID,
	sampleTerms
} from './helpers/conversion-terms-sample';

const INVALID = 'Invalid asset conversion terms';
const DOMAIN = 'beignet/asset-conversion/terms/v1\0';

const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();
const handDigest = (json: string): string =>
	sha256(
		Buffer.concat([Buffer.from(DOMAIN, 'ascii'), Buffer.from(json)])
	).toString('hex');
const hex = (d: Uint8Array): string => Buffer.from(d).toString('hex');

/** The to-plain sample as JSON, written by hand in the interface's key order. */
const TO_PLAIN_JSON =
	'{"version":1,"channelId":"' +
	'11'.repeat(32) +
	'","parent":{"txid":"' +
	SAMPLE_PARENT_TXID +
	'","outputIndex":1,"stateNumber":"4"},"direction":"to-plain",' +
	'"targetType":"0100000000000000000000","giver":"opener",' +
	'"candidate":{"dustLimitSats":{"opener":"354","acceptor":"354"},' +
	'"maxAcceptedHtlcs":{"opener":83,"acceptor":83}},' +
	'"contributions":{"opener":"0","acceptor":"-3000"},' +
	'"units":{"holder":"acceptor","issuances":[{"assetId":"' +
	'4c'.repeat(32) +
	'","amount":"1000"}]},' +
	'"firstCommitment":{"commitmentFeeratePerKw":253,' +
	'"balanceMsat":{"opener":"400000000","acceptor":"96000000"}},' +
	'"fees":{"fundingPayer":"acceptor","budgets":{"opener":"0","acceptor":"2500"},' +
	'"feeratePerKw":1000,"withdrawalPayer":"acceptor"},' +
	'"agreement":{"reference":"ff00","expiresAt":4102444800},"lockDepth":6}';
/** sha256(DOMAIN || TO_PLAIN_JSON), computed outside the code under test. */
const TO_PLAIN_DIGEST =
	'f1af31175fea7b9a6fadf6da3b9ff1a868e1e2afb5776bae579a91d685e86509';

/** The to-asset sample as JSON, written by hand. */
const TO_ASSET_JSON =
	'{"version":1,"channelId":"' +
	'11'.repeat(32) +
	'","parent":{"txid":"' +
	SAMPLE_PARENT_TXID +
	'","outputIndex":0,"stateNumber":"0"},"direction":"to-asset",' +
	'"targetType":"' +
	ASSET_SPLICE_RECOVERY_TYPE_HEX +
	'","giver":"acceptor",' +
	'"candidate":{"dustLimitSats":{"opener":"354","acceptor":"354"},' +
	'"maxAcceptedHtlcs":{"opener":83,"acceptor":83}},' +
	'"contributions":{"opener":"-1000","acceptor":"25000"},' +
	'"units":{"holder":"acceptor","issuances":[{"assetId":"' +
	'4c'.repeat(32) +
	'","amount":"1000"},{"assetId":"' +
	'5d'.repeat(32) +
	'","amount":"7"}]},' +
	'"firstCommitment":{"commitmentFeeratePerKw":253,' +
	'"balanceMsat":{"opener":"500000000","acceptor":"20000000"},' +
	'"units":[{"assetId":"' +
	'4c'.repeat(32) +
	'","opener":"0","acceptor":"1000"},{"assetId":"' +
	'5d'.repeat(32) +
	'","opener":"0","acceptor":"7"}]},' +
	'"fees":{"fundingPayer":"opener","budgets":{"opener":"2000","acceptor":"0"},' +
	'"feeratePerKw":1000},' +
	'"agreement":{"reference":"a1b2c3d4","expiresAt":4102444800},"lockDepth":3}';

/** The same object with every object's keys in reverse order, at every level. */
function reversedKeys(v: unknown): unknown {
	if (Array.isArray(v)) return v.map(reversedKeys);
	if (v === null || typeof v !== 'object') return v;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(v as object).reverse())
		out[key] = reversedKeys((v as Record<string, unknown>)[key]);
	return out;
}

type Mutable = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A copy of the sample of `direction` with one change made by `edit`. */
function edited(
	direction: IAssetConversionTerms['direction'],
	edit: (t: Mutable) => void
): IAssetConversionTerms {
	const t = copyTerms(sampleTerms({ direction })) as unknown as Mutable;
	edit(t);
	return t as unknown as IAssetConversionTerms;
}

/* eslint-disable @typescript-eslint/explicit-function-return-type -- the edits are typed by the table */
/** Structure, one field at a time: a missing or extra key, or a value of the wrong JSON type. */
const STRUCTURAL: [
	string,
	IAssetConversionTerms['direction'],
	(t: Mutable) => void
][] = [
	// Extra keys.
	['an extra top-level key', 'to-asset', (t) => (t.extra = 1)],
	['an extra key in parent', 'to-asset', (t) => (t.parent.extra = 1)],
	[
		'an extra key in candidate.dustLimitSats',
		'to-asset',
		(t) => (t.candidate.dustLimitSats.extra = '1')
	],
	[
		'an extra key in an issuance',
		'to-asset',
		(t) => (t.units.issuances[0].extra = '1')
	],
	[
		'an extra key in a first commitment unit',
		'to-asset',
		(t) => (t.firstCommitment.units[0].extra = '1')
	],
	['an extra key in fees', 'to-asset', (t) => (t.fees.extra = '1')],
	['an extra key in agreement', 'to-asset', (t) => (t.agreement.extra = 1)],
	// Missing keys.
	['a missing lockDepth', 'to-asset', (t) => delete t.lockDepth],
	['a missing version', 'to-plain', (t) => delete t.version],
	[
		'a missing parent.stateNumber',
		'to-asset',
		(t) => delete t.parent.stateNumber
	],
	[
		'a missing candidate.maxAcceptedHtlcs.acceptor',
		'to-asset',
		(t) => delete t.candidate.maxAcceptedHtlcs.acceptor
	],
	['a missing units.issuances', 'to-plain', (t) => delete t.units.issuances],
	['a missing fees.budgets', 'to-plain', (t) => delete t.fees.budgets],
	[
		'a missing agreement.expiresAt',
		'to-plain',
		(t) => delete t.agreement.expiresAt
	],
	// Wrong JSON types.
	['a version as a string', 'to-asset', (t) => (t.version = '1')],
	['a channel id as a number', 'to-asset', (t) => (t.channelId = 11)],
	['a parent txid as a number', 'to-asset', (t) => (t.parent.txid = 22)],
	[
		'an output index as a string',
		'to-asset',
		(t) => (t.parent.outputIndex = '0')
	],
	['a state number as a number', 'to-asset', (t) => (t.parent.stateNumber = 0)],
	['a target type as an array', 'to-plain', (t) => (t.targetType = [1])],
	[
		'a dust limit as a number',
		'to-asset',
		(t) => (t.candidate.dustLimitSats.opener = 354)
	],
	[
		'an HTLC limit as a string',
		'to-asset',
		(t) => (t.candidate.maxAcceptedHtlcs.opener = '83')
	],
	[
		'a contribution as a number',
		'to-asset',
		(t) => (t.contributions.opener = -1000)
	],
	['issuances as an object', 'to-plain', (t) => (t.units.issuances = {})],
	['an issuance as a string', 'to-plain', (t) => (t.units.issuances = ['4c'])],
	[
		'an issuance amount as a number',
		'to-plain',
		(t) => (t.units.issuances[0].amount = 1000)
	],
	[
		'a commitment feerate as a string',
		'to-asset',
		(t) => (t.firstCommitment.commitmentFeeratePerKw = '253')
	],
	[
		'a balance as a number',
		'to-asset',
		(t) => (t.firstCommitment.balanceMsat.opener = 500000000)
	],
	[
		'first commitment units as an object',
		'to-asset',
		(t) => (t.firstCommitment.units = {})
	],
	[
		'a first commitment unit amount as a number',
		'to-asset',
		(t) => (t.firstCommitment.units[0].acceptor = 1000)
	],
	[
		'a fee budget as a number',
		'to-asset',
		(t) => (t.fees.budgets.opener = 2000)
	],
	[
		'a funding feerate as a string',
		'to-asset',
		(t) => (t.fees.feeratePerKw = '1000')
	],
	['a reference as a number', 'to-asset', (t) => (t.agreement.reference = 12)],
	[
		'an expiry as a string',
		'to-asset',
		(t) => (t.agreement.expiresAt = '4102444800')
	],
	['a lock depth as a string', 'to-asset', (t) => (t.lockDepth = '3')],
	['a null lock depth', 'to-asset', (t) => (t.lockDepth = null)],
	['a null parent', 'to-asset', (t) => (t.parent = null)],
	['agreement as an array', 'to-plain', (t) => (t.agreement = [])]
];
/* eslint-enable @typescript-eslint/explicit-function-return-type */

/** The directions a grammar case runs in. */
const directionsOf = (
	applies: (typeof GRAMMAR_CASES)[number]['applies']
): IAssetConversionTerms['direction'][] =>
	applies === 'both' ? ['to-asset', 'to-plain'] : [applies];

/** Terms shaped as a live channel builds them: one issuance and no contributions. */
function channelShaped(
	direction: IAssetConversionTerms['direction']
): IAssetConversionTerms {
	const t = copyTerms(sampleTerms({ direction }));
	t.contributions = { opener: '0', acceptor: '0' };
	t.units.issuances = [{ assetId: SAMPLE_ASSET_A, amount: '1000' }];
	if (direction === 'to-asset')
		t.firstCommitment.units = [
			{ assetId: SAMPLE_ASSET_A, opener: '0', acceptor: '1000' }
		];
	return t;
}

describe('Asset conversion terms: canonical form and digest (#2151 step 3a, test 2)', function () {
	it('writes the canonical bytes of each variant exactly as written by hand', () => {
		const { canonicalAssetConversionTerms } = conversionTerms();
		expect(
			JSON.stringify(
				canonicalAssetConversionTerms(sampleTerms({ direction: 'to-plain' }))
			)
		).to.equal(TO_PLAIN_JSON);
		expect(
			JSON.stringify(
				canonicalAssetConversionTerms(sampleTerms({ direction: 'to-asset' }))
			)
		).to.equal(TO_ASSET_JSON);
		expect(TO_PLAIN_JSON).to.match(/^[\x21-\x7e]+$/);
	});

	it('pins the digest of the canonical bytes under the terms domain', () => {
		const { assetConversionTermsDigest } = conversionTerms();
		expect(handDigest(TO_PLAIN_JSON)).to.equal(TO_PLAIN_DIGEST);
		const plain = assetConversionTermsDigest(
			sampleTerms({ direction: 'to-plain' })
		);
		expect(plain).to.have.length(32);
		expect(hex(plain)).to.equal(TO_PLAIN_DIGEST);
		expect(
			hex(assetConversionTermsDigest(sampleTerms({ direction: 'to-asset' })))
		).to.equal(handDigest(TO_ASSET_JSON));
	});

	it("gives the same canonical bytes and digest whatever a host's key order", () => {
		const { canonicalAssetConversionTerms, assetConversionTermsDigest } =
			conversionTerms();
		for (const direction of ['to-plain', 'to-asset'] as const) {
			const terms = sampleTerms({ direction });
			const shuffled = reversedKeys(terms) as IAssetConversionTerms;
			expect(JSON.stringify(shuffled)).not.to.equal(JSON.stringify(terms));
			expect(JSON.stringify(canonicalAssetConversionTerms(shuffled))).to.equal(
				JSON.stringify(canonicalAssetConversionTerms(terms))
			);
			expect(hex(assetConversionTermsDigest(shuffled))).to.equal(
				hex(assetConversionTermsDigest(terms))
			);
		}
	});

	it('adds no optional key that the terms leave out', () => {
		const { canonicalAssetConversionTerms } = conversionTerms();
		const toAsset = canonicalAssetConversionTerms(sampleTerms());
		expect(toAsset.fees).not.to.have.property('withdrawalPayer');
		const toPlain = canonicalAssetConversionTerms(
			sampleTerms({ direction: 'to-plain' })
		);
		expect(toPlain.firstCommitment).not.to.have.property('units');
	});

	for (const [label, direction, edit] of STRUCTURAL)
		it(`refuses ${label}`, () => {
			const { canonicalAssetConversionTerms, assetConversionTermsDigest } =
				conversionTerms();
			const terms = edited(direction, edit);
			expect(() => canonicalAssetConversionTerms(terms)).to.throw(INVALID);
			expect(() => assetConversionTermsDigest(terms)).to.throw(INVALID);
		});

	// The value grammar is the numbered checks' (amendment v3.1 item 3), so the
	// canonical form keeps each violation and the digest covers it.
	for (const c of GRAMMAR_CASES)
		for (const direction of directionsOf(c.applies))
			it(`keeps ${c.what} (${direction}) in the canonical form and digests it`, () => {
				const { canonicalAssetConversionTerms, assetConversionTermsDigest } =
					conversionTerms();
				const terms = copyTerms(sampleTerms({ direction }));
				const before = JSON.stringify(terms);
				c.change(terms);
				const json = JSON.stringify(terms);
				expect(json, 'the case changes the terms').not.to.equal(before);
				expect(JSON.stringify(canonicalAssetConversionTerms(terms))).to.equal(
					json
				);
				expect(hex(assetConversionTermsDigest(terms))).to.equal(
					handDigest(json)
				);
			});

	it('changes terms shaped as a live channel builds them, for every grammar case', () => {
		for (const c of GRAMMAR_CASES)
			for (const direction of directionsOf(c.applies)) {
				const terms = channelShaped(direction);
				const before = JSON.stringify(terms);
				c.change(terms);
				expect(JSON.stringify(terms), c.what + ' ' + direction).not.to.equal(
					before
				);
			}
		const texts = new Set(GRAMMAR_CASES.map((c) => c.text));
		expect(texts.size).to.equal(10);
	});

	it("refuses values outside the interface's unions", () => {
		const { canonicalAssetConversionTerms } = conversionTerms();
		const unions: ((t: Mutable) => void)[] = [
			(t): void => {
				t.giver = 'buyer';
			},
			(t): void => {
				t.units.holder = 'local';
			},
			(t): void => {
				t.fees.fundingPayer = 'both';
			},
			(t): void => {
				t.direction = 'sideways';
			}
		];
		for (const edit of unions)
			expect(() =>
				canonicalAssetConversionTerms(edited('to-asset', edit))
			).to.throw(INVALID);
		expect(() =>
			canonicalAssetConversionTerms(
				edited('to-plain', (t): void => {
					t.fees.withdrawalPayer = 'remote';
				})
			)
		).to.throw(INVALID);
	});

	it('keeps the sample expiry a safe integer in the future', () => {
		// The sample is shared with the agreement tests; its expiry must stay valid.
		expect(Number.isSafeInteger(SAMPLE_EXPIRES_AT)).to.equal(true);
		// Unix seconds (amendment v3.1 item 4).
		expect(SAMPLE_EXPIRES_AT).to.be.greaterThan(Math.floor(Date.now() / 1000));
		expect(SAMPLE_EXPIRES_AT).to.be.lessThan(2 ** 32);
	});
});

/** The fields each peer checks, derived from its own store only. */
function ownView(
	store: SqliteStorage,
	id: string,
	naming: 'roles' | 'local-remote'
): Pick<
	IAssetConversionTerms,
	'channelId' | 'parent' | 'direction' | 'targetType' | 'candidate'
> & {
	commitmentFeeratePerKw: number;
	balanceMsat: { opener: string; acceptor: string };
} {
	const opening = store.loadFinalDaemonOpening(id)!;
	const { terms, updateLimits } = opening.session;
	const current = store.loadFinalChannelType(id)!;
	const me = naming === 'local-remote' || opening.candidate.isInitiator;
	// Name a pair of this side's (local) and the peer's (remote) values by role.
	const byRole = <T>(local: T, remote: T): { opener: T; acceptor: T } =>
		me
			? { opener: local, acceptor: remote }
			: { opener: remote, acceptor: local };
	let stateNumber: string,
		feerate: number,
		balances: { local: bigint; remote: bigint };
	if (current.type === 'plain') {
		const status = store.loadFinalUpdateStatus(id)!;
		stateNumber = status.localHeight.toString();
		feerate = status.feeratePerKw ?? terms.commitmentFeeratePerKw;
		balances = {
			local: status.localBalanceMsat,
			remote: status.remoteBalanceMsat
		};
	} else {
		const head = store.assetSpliceUpdateHead(id);
		stateNumber = String(head.committed?.height ?? '0');
		feerate = head.committed?.feerate ?? terms.commitmentFeeratePerKw;
		balances = { local: 0n, remote: 0n };
	}
	return {
		channelId: id,
		parent: {
			txid: current.funding.txid,
			outputIndex: current.funding.outputIndex,
			stateNumber
		},
		direction: current.type === 'plain' ? 'to-asset' : 'to-plain',
		targetType:
			current.type === 'plain'
				? ASSET_SPLICE_RECOVERY_TYPE_HEX
				: PLAIN_TARGET_TYPE_HEX,
		candidate: {
			dustLimitSats: byRole(
				String(terms.localDustLimitSatoshis),
				String(terms.remoteDustLimitSatoshis)
			),
			maxAcceptedHtlcs: byRole(
				updateLimits!.local.maxAcceptedHtlcs,
				updateLimits!.remote.maxAcceptedHtlcs
			)
		},
		commitmentFeeratePerKw: feerate,
		balanceMsat: byRole(balances.local.toString(), balances.remote.toString())
	};
}

/** Terms built by one peer: the agreed amounts by role, the rest from its own view. */
function termsFrom(view: ReturnType<typeof ownView>): IAssetConversionTerms {
	const base = sampleTerms({ direction: view.direction });
	return {
		...base,
		channelId: view.channelId,
		parent: view.parent,
		direction: view.direction,
		targetType: view.targetType,
		candidate: view.candidate,
		firstCommitment: {
			...base.firstCommitment,
			commitmentFeeratePerKw: view.commitmentFeeratePerKw,
			balanceMsat: view.balanceMsat
		}
	};
}

describe('Asset conversion terms: symmetry between the peers (#2151 step 3a, test 2)', function () {
	this.timeout(60000);
	let s: Scratch;
	// The pairs are only read, so the tests share them.
	let shared: Promise<
		{ label: string; id: string; stores: SqliteStorage[]; sided: boolean }[]
	>;
	before(() => {
		s = scratch('asset-conversion-terms-');
		shared = build();
		// A failure surfaces in the test that awaits it.
		shared.catch(() => undefined);
	});
	after(() => s.release());
	const pairs = (): typeof shared => shared;

	async function build(): Promise<
		{ label: string; id: string; stores: SqliteStorage[]; sided: boolean }[]
	> {
		const fit = plainTypePair(s, 1, 6);
		// The fixture's own terms: dust 354 on the opener's side, 1000 on the acceptor's.
		const sided = plainTypePair(s, 0, 6, {});
		const asset = await assetTypePair(s, 1, 6);
		return [
			{
				label: 'plain at FIT_TERMS',
				id: fit.id,
				stores: fit.stores,
				sided: false
			},
			{
				label: 'plain with sided dust',
				id: sided.id,
				stores: sided.stores,
				sided: true
			},
			{
				label: 'asset of the recovery profile',
				id: asset.id,
				stores: asset.devices.map((d) => d.store),
				sided: true
			}
		];
	}

	it("derives equal terms on both sides from each side's own store, so both digests agree", async () => {
		const { canonicalAssetConversionTerms, assetConversionTermsDigest } =
			conversionTerms();
		for (const { label, id, stores } of await pairs()) {
			const opener = stores.findIndex(
				(st) => st.loadFinalDaemonOpening(id)!.candidate.isInitiator
			);
			expect(opener, label).to.be.oneOf([0, 1]);
			const built = stores.map((st) => termsFrom(ownView(st, id, 'roles')));
			expect(
				JSON.stringify(canonicalAssetConversionTerms(built[0])),
				label
			).to.equal(JSON.stringify(canonicalAssetConversionTerms(built[1])));
			expect(hex(assetConversionTermsDigest(built[0])), label).to.equal(
				hex(assetConversionTermsDigest(built[1]))
			);
		}
	});

	it('would disagree if a side named the fields local and remote instead of by role', async () => {
		const { assetConversionTermsDigest } = conversionTerms();
		for (const { label, id, stores, sided } of await pairs()) {
			if (!sided) continue;
			const naive = stores.map((st) =>
				termsFrom(ownView(st, id, 'local-remote'))
			);
			expect(JSON.stringify(naive[0].candidate), label).not.to.equal(
				JSON.stringify(naive[1].candidate)
			);
			expect(hex(assetConversionTermsDigest(naive[0])), label).not.to.equal(
				hex(assetConversionTermsDigest(naive[1]))
			);
		}
	});

	it("reads a plain parent's feerate after an update_fee round, not the opening's", () => {
		const pair = plainTypePair(s, 1, 6);
		for (const st of pair.stores) {
			const view = ownView(st, pair.id, 'roles');
			expect(view.commitmentFeeratePerKw).to.equal(300);
			expect(
				st.loadFinalDaemonOpening(pair.id)!.session.terms.commitmentFeeratePerKw
			).not.to.equal(300);
			expect(view.parent.stateNumber).to.equal('1');
		}
	});
});
