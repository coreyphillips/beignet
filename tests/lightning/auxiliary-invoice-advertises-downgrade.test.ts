/**
 * Issue #2098, step 10: the released 0.44.0 over the database of a payee
 * that made an asset invoice.
 *
 * Carol runs this build and makes an asset invoice whose one hint names
 * Bob, the edge node that turns Alice's bitcoin into units for her. Her host
 * leaves receiveInParts out, so the invoice offers no basic_mpp and a payer
 * sends it whole. She is then stopped, and the published LightningNode of
 * 0.44.0 is started over her database, on the same chain, with this tree's
 * reference provider and the hooks she had. It reads back the record this
 * build wrote, and the one asset HTLC that pays the invoice settles there.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_44_0 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.44.0
 *   BEIGNET_RELEASED_0_44_0="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/auxiliary-invoice-advertises-downgrade.test.ts
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import type { IRoutingHintHop } from '../../src/lightning/invoice/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import {
	aliasOf,
	forwardChainWorld,
	sendPart,
	type IPartsInvoice
} from './helpers/auxiliary-forward-world';
import {
	listenCarol,
	openPartsScene,
	type IPartsScene
} from './helpers/auxiliary-forward-scene';
import { assetInvoiceOptions } from './helpers/auxiliary-invoice';
import {
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsReceived,
	type IEngineBuild
} from './helpers/auxiliary-nodes';
import {
	alicePaid,
	asksFor,
	carolsRecord,
	heldOn,
	hex,
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

/** A record with the keys that hold nothing left out, as storage gives it back. */
const plain = (record: object): Record<string, unknown> =>
	Object.fromEntries(
		Object.entries(record).filter(([, value]) => value !== undefined)
	);

describe('the released 0.44.0 over a payee that made an asset invoice (issue #2098, step 10)', function () {
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

	/** Stop Carol and start 0.44.0 over her database, with the hooks she had; her logs are kept from the start. */
	async function downgrade(s: IPartsScene, tag: string): Promise<void> {
		const build = released();
		await world.restartCarol(s.w, tag, {
			build,
			wrapProvider: (provider) => provider,
			reconnect: false
		});
		expect(
			s.w.hosts.carol.node,
			'Carol runs the released build'
		).to.be.instanceOf(build.LightningNode);
		listenCarol(s);
		await world.reconnect(s.w, 'out');
	}

	it('an asset invoice of a host that leaves receiveInParts out is read back by 0.44.0 as this build wrote it, and the one asset HTLC that pays it settles there', async () => {
		const tag = 'asset-invoice-downgrade';
		const s = await openPartsScene(world, tag, {
			optIn: false,
			world: { carolOnFile: true }
		});
		const bobId = Buffer.from(s.w.hosts.bob.node.getNodeId(), 'hex');
		const edge: IRoutingHintHop = {
			pubkey: bobId,
			shortChannelId: aliasOf(s.w.hosts.bob, s.w.outChannel),
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			cltvExpiryDelta: 40
		};
		const made = s.w.hosts.carol.node.createInvoice(
			assetInvoiceOptions({
				amountMsat: 5_000_000n,
				description: `asset invoice ${tag}`,
				extraRoutingHints: [[edge]]
			})
		);
		const written = plain(
			s.w.hosts.carol.node.getInvoice(hex(made.paymentHash))!
		);

		await downgrade(s, tag);
		const read = s.w.hosts.carol.node.getInvoice(hex(made.paymentHash));
		expect(read, '0.44.0 has the invoice').to.not.equal(null);
		expect(plain(read!)).to.deep.equal(written);

		// Alice pays it whole, through the hop its hint names.
		const hint = decodeInvoice(read!.bolt11).routingHints!.find((hops) =>
			hops[hops.length - 1].pubkey.equals(bobId)
		)!;
		const invoice: IPartsInvoice = {
			paymentHash: made.paymentHash,
			paymentSecret: made.paymentSecret,
			invoiceMsat: 5_000_000n,
			totalMsat: 5_000_000n
		};
		sendPart(s.w, invoice, 5_000_000n, {
			next: hint[hint.length - 1].shortChannelId
		});
		await alicePaid(s, invoice);
		await turns(50);
		expect(asksFor(s, invoice).length, 'one asset HTLC reached Carol').to.equal(
			1
		);
		expect(carolsRecord(s, invoice)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(heldOn(s.w.hosts.carol, s.w.outChannel, made.paymentHash)).to.equal(
			0
		);
		// The 5000 units moved to Carol, who held 1000.
		expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
	});
});
