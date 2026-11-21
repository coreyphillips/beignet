/**
 * Issue #2098, step 8: the released 0.44.0 over the database of a payee
 * that took an asset invoice in parts ("Going back to an earlier build",
 * under "An asset invoice paid in parts" in docs/EXTENSIONS.md).
 *
 * Carol runs this build and collects or commits a set of asset parts; she
 * is then stopped, and the published LightningNode of 0.44.0 is started
 * over her database, on the same chain, and joined to this build's Bob
 * through message:outbound and handlePeerMessage, as connectNodes does, with
 * this tree's reference provider. A committed set is listed in its record,
 * so 0.44.0 fulfils a part the record lists on its reestablish and claims a
 * part whose settle decision was written on the chain; a set being collected
 * lives in memory only, so 0.44.0 puts its part through its own gate and
 * fails it back.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_44_0 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.44.0
 *   BEIGNET_RELEASED_0_44_0="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/auxiliary-receive-parts-downgrade.test.ts
 *
 * Written first: on the base no set of asset parts is collected, so each
 * case fails where this build is to collect or commit the set.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	forwardChainWorld,
	partsInvoice,
	payInParts,
	sendPart
} from './helpers/auxiliary-forward-world';
import {
	listenCarol,
	openPartsScene,
	rounds,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import {
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	type IEngineBuild
} from './helpers/auxiliary-nodes';
import { SWEEP_DESTINATION } from './helpers/auxiliary-on-chain';
import {
	alicePaid,
	alicesStatus,
	carolsRecord,
	claimedByPreimage,
	collected,
	committed,
	decisionOf,
	heldOn,
	hex,
	keeping,
	keyOf,
	onCommit,
	openReceived,
	partsOf,
	receivedEntries,
	refusing,
	unitsOf
} from './helpers/auxiliary-parts-checks';

const RELEASED = process.env.BEIGNET_RELEASED_0_44_0;

/** The released build's node and storage, as its dist has them. */
const released = (): IEngineBuild => {
	const from = (file: string): Record<string, unknown> =>
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		require(path.join(RELEASED as string, 'dist', 'lightning', file));
	return {
		LightningNode: from('node/lightning-node.js')
			.LightningNode as IEngineBuild['LightningNode'],
		SqliteStorage: from('storage/sqlite-storage.js')
			.SqliteStorage as IEngineBuild['SqliteStorage']
	};
};

describe('the released 0.44.0 over a payee that took an asset invoice in parts (issue #2098, step 8)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	before(function () {
		if (!RELEASED) this.skip();
		const manifest = JSON.parse(
			fs.readFileSync(path.join(RELEASED as string, 'package.json'), 'utf8')
		) as { name: string; version: string };
		expect([manifest.name, manifest.version]).to.deep.equal([
			'beignet',
			'0.44.0'
		]);
	});

	/**
	 * Stop Carol and start 0.44.0 over her database, with the reference
	 * provider and the hooks she had; her logs are kept from the start.
	 */
	async function downgrade(
		s: IPartsScene,
		tag: string,
		options: { whileDown?: () => void; reconnect?: boolean } = {}
	): Promise<IEngineBuild> {
		const build = released();
		await world.restartCarol(s.w, tag, {
			build,
			wrapProvider: (provider) => provider,
			reconnect: false,
			...(options.whileDown ? { whileDown: options.whileDown } : {})
		});
		expect(
			s.w.hosts.carol.node,
			'Carol runs the released build'
		).to.be.instanceOf(build.LightningNode);
		listenCarol(s);
		if (options.reconnect !== false) await world.reconnect(s.w, 'out');
		return build;
	}

	/** Bob's HTLCs to Carol for a hash, still in his channel. */
	const offeredBy = (s: IPartsScene, paymentHash: Buffer): number =>
		[
			...(s.w.hosts.bob.node
				.getChannelManager()
				.getChannel(s.w.outChannel)
				?.getFullState().htlcs ?? new Map())
		].filter(
			([key, entry]) =>
				key.startsWith('offered-') && entry.paymentHash.equals(paymentHash)
		).length;

	it('a committed set with one part unfulfilled: 0.44.0 fulfils the part its record lists on the reestablish, and the set is paid whole', async () => {
		const tag = 'parts-downgrade-committed';
		const keep = { keep: new Set<string>() };
		const s = await openPartsScene(world, tag, {
			world: { carolOnFile: true, wrapProvider: { carol: keeping(keep) } }
		});
		// At the commit, the fulfil of one part is refused.
		onCommit(s, () => {
			const parts = openReceived(s.w.hosts.carol, s.w.outChannel);
			keep.keep.add(keyOf(s.w.outChannel, parts[parts.length - 1].id));
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const left = receivedEntries(
			s.w.hosts.carol,
			s.w.outChannel,
			invoice.paymentHash
		);
		expect(left.length, 'one part is unfulfilled').to.equal(1);
		expect(decisionOf(s.w.hosts.carol, s.w.outChannel, left[0].id)).to.equal(
			'settle'
		);

		await downgrade(s, tag);
		await rounds(
			'0.44.0 fulfils the part',
			() =>
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash) === 0 &&
				offeredBy(s, invoice.paymentHash) === 0,
			60
		);
		await alicePaid(s, invoice);
		expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
		const record = carolsRecord(s, invoice)!;
		expect(record.status).to.equal(PaymentStatus.COMPLETED);
		expect(record.settledHtlcs?.length).to.equal(2);
		expect(Object.keys(partsOf(record) ?? {}).length).to.equal(2);
	});

	it('a set being collected: 0.44.0 puts its part through its own gate and fails it back, and nothing is settled', async () => {
		const tag = 'parts-downgrade-collecting';
		const s = await openPartsScene(world, tag, {
			world: { carolOnFile: true }
		});
		const invoice = partsInvoice(s.w, tag, 5_000_000n);
		sendPart(s.w, invoice, 3_000_000n);
		await rounds(
			'Carol holds the first part in the set',
			() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
		);
		const mark = s.carolLogs.length;
		await downgrade(s, tag);
		await rounds(
			'0.44.0 refuses the part',
			() =>
				s.carolLogs
					.slice(mark)
					.some(
						(log) =>
							log.action === 'asset_multi_part_refused' &&
							log.data.paymentHash === hex(invoice.paymentHash)
					),
			60
		);
		await rounds(
			'the payment fails at Alice',
			() => alicesStatus(s, invoice) === PaymentStatus.FAILED,
			60
		);
		expect(
			heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash)
		).to.equal(0);
		expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(1000n);
		expect(carolsRecord(s, invoice)?.status).to.not.equal(
			PaymentStatus.COMPLETED
		);
		expect(
			s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.preimage
		).to.equal(undefined);
	});

	it('a committed part with its decision written, on a channel Bob takes to the chain while Carol is down: 0.44.0 claims it there by its preimage before its expiry', async () => {
		const tag = 'parts-downgrade-chain';
		const arm = { down: false };
		const s = await openPartsScene(world, tag, {
			world: { carolOnFile: true, wrapProvider: { carol: refusing(arm) } },
			coins: 4
		});
		onCommit(s, () => {
			arm.down = true;
		});
		const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
		await committed(s, invoice);
		await turns(50);
		const parts = receivedEntries(
			s.w.hosts.carol,
			s.w.outChannel,
			invoice.paymentHash
		);
		expect(parts.length, 'both fulfils were refused').to.equal(2);
		for (const part of parts) {
			expect(decisionOf(s.w.hosts.carol, s.w.outChannel, part.id)).to.equal(
				'settle'
			);
		}
		const expiry = Math.min(...parts.map((part) => part.cltvExpiry));

		await downgrade(s, tag, {
			reconnect: false,
			whileDown: () => {
				const closed = s.w.hosts.bob.node.forceCloseChannel(
					s.w.outChannel,
					SWEEP_DESTINATION
				);
				expect(closed.ok, closed.error).to.equal(true);
			}
		});
		for (
			let i = 0;
			i < 30 &&
			claimedByPreimage(s, s.w.outChannel, invoice.paymentHash).length < 2;
			i++
		) {
			await world.mine(s.w, 1);
		}
		const claimed = claimedByPreimage(s, s.w.outChannel, invoice.paymentHash);
		expect(claimed.length, '0.44.0 claims both parts').to.equal(2);
		for (const output of claimed) {
			expect(output.confirmationHeight).to.be.lessThan(expiry);
		}
		await alicePaid(s, invoice);
		expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.COMPLETED);
	});
});
