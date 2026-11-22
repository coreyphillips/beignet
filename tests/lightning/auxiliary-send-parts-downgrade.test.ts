/**
 * Issue #2098, step 9: the released 0.44.0 over the database of a payer
 * that sent an asset payment in parts ("Going back to an earlier build",
 * under "An asset payment sent in parts" in docs/EXTENSIONS.md).
 *
 * Alice runs this build, with her host's opt-in (`sendInParts`) and the
 * build's switch, and holds two asset channels with Bob. Bob values each
 * unit she sends at a satoshi and forwards what she sends to Carol over an
 * ordinary channel, where Carol collects the parts as any multi-part set.
 * Alice pays Carol's invoice in two parts, one over each channel; the
 * second fails at Bob, and she sends it again. Carol settles the set, and
 * the fulfils Bob sends Alice are lost: Alice is stopped with both parts
 * out. The published LightningNode of 0.44.0 is then started over her
 * database (her host no longer sets `sendInParts`, as before a downgrade),
 * and joined to this build's Bob through message:outbound and
 * handlePeerMessage, as the loopback nodes are, with this tree's reference
 * provider. An earlier build knows one HTLC per asset payment: it reads
 * the record by the first part's channel and ends each part through its
 * mapping, and a fulfil completes the record. Nothing is lost: every HTLC
 * ends in its channel, and the units on each channel are what was paid.
 *
 * A payment of one HTLC from the same payer goes through the same stop and
 * start; it holds on a build before this step as well.
 *
 * The released build is not a dependency of this repository. The suite runs
 * when BEIGNET_RELEASED_0_44_0 names an installed copy of it, and is skipped
 * without it:
 *
 *   npm install --prefix "$DIR" beignet@0.44.0
 *   BEIGNET_RELEASED_0_44_0="$DIR/node_modules/beignet" \
 *     npx mocha -r ts-node/register tests/lightning/auxiliary-send-parts-downgrade.test.ts
 *
 * Written first: on the base an asset payment cannot be sent in parts, so
 * the case of the parts fails at its first part.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	SEND_IN_PARTS,
	assetHost,
	openAssetChannel,
	turns,
	withAssetForwards,
	withAssetOpens,
	withAssetPartsSent,
	type IAssetHost,
	type IEngineBuild
} from './helpers/auxiliary-nodes';
import { amountRecord } from './helpers/auxiliary-pair';
import { connectNodes, openReadyChannel } from './helpers/loopback-nodes';

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

/** The message that carries a fulfil (BOLT 2). */
const UPDATE_FULFILL_HTLC = 130;

/** What Bob's host values each unit at, and the bitcoin each asset HTLC carries. */
const MSAT_PER_UNIT = 1000n;
const CARRIER_MSAT = 354_000n;
/** The units Alice pays Bob above what he forwards, for his fee. */
const FEE_UNITS = 10n;
/** What each of Alice's asset channels holds: hers, then Bob's. */
const ALICE_UNITS = 9000n;
const BOB_UNITS = 1000n;
/** A next hop no channel of Bob's has. */
const NOWHERE = Buffer.alloc(8, 0x77);

const sha256 = (data: Buffer): Buffer =>
	crypto.createHash('sha256').update(data).digest();

type Name = 'alice' | 'bob' | 'carol';

/** An outcome of an asset HTLC that Alice's host was told of. */
interface IOutcome {
	channelId: string;
	htlcId: bigint;
	outcome: string;
}

interface IPayerWorld {
	tag: string;
	/** Alice's database file, from which the released build starts. */
	alicePath: string;
	hosts: Record<Name, IAssetHost>;
	/** Alice's two asset channels with Bob. */
	first: Buffer;
	second: Buffer;
	/** Bob's ordinary channel with Carol. */
	out: Buffer;
	/**
	 * Alice's link with Bob. With `loseFulfils`, the first fulfil Bob sends
	 * her is lost, and everything after it, both ways.
	 */
	link: { up: boolean; loseFulfils: boolean };
	/** What Alice's node emitted and her host was told, on either build. */
	sent: string[];
	failed: string[];
	outcomes: IOutcome[];
}

/** An invoice of Carol's, which Alice pays. */
interface IInvoice {
	paymentHash: Buffer;
	paymentSecret: Buffer;
}

/** Message rounds until `reached`, or throw with what is missing. */
async function rounds(
	what: string,
	reached: () => boolean,
	most = 60
): Promise<void> {
	for (let i = 0; i < most && !reached(); i++) await turns(5);
	if (!reached()) throw new Error(`never reached: ${what}`);
}

describe('the released 0.44.0 over a payer that sent an asset payment in parts (issue #2098, step 9)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsSent();

	const made: IAssetHost[] = [];
	const files: string[] = [];
	afterEach(() => {
		for (const host of made.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// Stopped already.
			}
			try {
				host.storage?.close();
			} catch {
				// Closed already.
			}
		}
		for (const file of files.splice(0)) fs.rmSync(file, { force: true });
	});

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

	/** Alice's hooks: what her host is told of each asset HTLC, and the opt-in. */
	const aliceHooks = (
		w: IPayerWorld,
		optIn: boolean
	): Partial<IAuxiliaryChannelConfig> => ({
		...(optIn ? SEND_IN_PARTS : {}),
		onHtlcResolved: (context): void => {
			w.outcomes.push({
				channelId: context.channelId.toString('hex'),
				htlcId: context.htlcId,
				outcome: context.outcome
			});
		}
	});

	/** Bob's host: it values each unit Alice sends at a satoshi, and forwards it in bitcoin. */
	const bobHooks: Partial<IAuxiliaryChannelConfig> = {
		prepareForward: (request) =>
			request.incoming.auxiliaryAmount === undefined
				? undefined
				: {
						incomingValueMsat: request.incoming.auxiliaryAmount * MSAT_PER_UNIT
				  },
		onForwardLegResolved: (): void => undefined
	};

	/** Alice's node's payment events, kept on the world; again after a restart. */
	const listenAlice = (w: IPayerWorld): void => {
		const node = w.hosts.alice.node;
		node.on('payment:sent', (info: { paymentHash: Buffer }) => {
			w.sent.push(info.paymentHash.toString('hex'));
		});
		node.on('payment:failed', (info: { paymentHash: Buffer }) => {
			w.failed.push(info.paymentHash.toString('hex'));
		});
	};

	/**
	 * What one of Alice and Bob sends the other passes while their link is
	 * up. The receiver is read at each message, so a node that replaces
	 * Alice is the one reached.
	 */
	const wire = (w: IPayerWorld, from: 'alice' | 'bob'): void => {
		const to = from === 'alice' ? 'bob' : 'alice';
		const sender = w.hosts[from].node;
		sender.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				const receiver = w.hosts[to].node;
				if (pubkey !== receiver.getNodeId()) return;
				if (
					from === 'bob' &&
					type === UPDATE_FULFILL_HTLC &&
					w.link.loseFulfils
				) {
					w.link.up = false;
				}
				if (!w.link.up) return;
				receiver.handlePeerMessage(sender.getNodeId(), type, payload);
			}
		);
	};

	/** Alice and Bob stop hearing each other, and each is told. */
	const cut = (w: IPayerWorld): void => {
		w.link.up = false;
		const { alice, bob } = w.hosts;
		alice.node.getChannelManager().handlePeerDisconnected(bob.node.getNodeId());
		bob.node.getChannelManager().handlePeerDisconnected(alice.node.getNodeId());
	};

	/**
	 * Alice and Bob hear each other again and reestablish. Both learn of the
	 * new connection before either reads a message of it, and what is sent
	 * meanwhile is delivered in the order sent.
	 */
	const reconnect = async (w: IPayerWorld): Promise<void> => {
		const pair = [w.hosts.alice, w.hosts.bob];
		const held: Array<() => void> = [];
		const originals = pair.map((host) => host.node.handlePeerMessage);
		for (const host of pair) {
			const deliver = host.node.handlePeerMessage.bind(host.node);
			host.node.handlePeerMessage = ((
				peer: string,
				type: number,
				payload: Buffer
			) => {
				held.push(() => deliver(peer, type, payload));
			}) as typeof host.node.handlePeerMessage;
		}
		w.link.loseFulfils = false;
		w.link.up = true;
		const [a, b] = pair;
		a.node.getChannelManager().handlePeerReconnected(b.node.getNodeId());
		b.node.getChannelManager().handlePeerReconnected(a.node.getNodeId());
		while (held.length > 0) held.shift()!();
		a.node.handlePeerMessage = originals[0];
		b.node.handlePeerMessage = originals[1];
		await turns(100);
	};

	/**
	 * Alice, on this build from her database file, with two asset channels
	 * with Bob; Bob, with an ordinary channel to Carol that he opened.
	 */
	const openWorld = async (tag: string): Promise<IPayerWorld> => {
		const alicePath = path.join(
			os.tmpdir(),
			`${tag}-alice-${process.pid}-${crypto
				.randomBytes(4)
				.toString('hex')}.sqlite`
		);
		files.push(alicePath, `${alicePath}-wal`, `${alicePath}-shm`);
		const w = {
			tag,
			alicePath,
			link: { up: true, loseFulfils: false },
			sent: [],
			failed: [],
			outcomes: []
		} as unknown as IPayerWorld;
		const alice = assetHost(tag, 1, aliceHooks(w, true), {
			sqlitePath: alicePath
		});
		const bob = assetHost(tag, 2, bobHooks, { sqlite: true });
		const carol = assetHost(tag, 3, {}, { sqlite: true });
		made.push(alice, bob, carol);
		w.hosts = { alice, bob, carol };
		listenAlice(w);
		wire(w, 'alice');
		wire(w, 'bob');
		connectNodes(bob.node, carol.node);
		w.first = await openAssetChannel(alice, bob, {
			tag: `${tag} first`,
			openerUnits: ALICE_UNITS,
			acceptorUnits: BOB_UNITS
		});
		w.second = await openAssetChannel(alice, bob, {
			tag: `${tag} second`,
			openerUnits: ALICE_UNITS,
			acceptorUnits: BOB_UNITS
		});
		w.out = openReadyChannel(bob.node, carol.node, 2_000_000n);
		await turns(50);
		return w;
	};

	/** Carol's invoice for `amountMsat`: an ordinary one, settled once paid. */
	const invoiceOf = (
		w: IPayerWorld,
		amountMsat: bigint,
		description: string
	): IInvoice => {
		const invoice = w.hosts.carol.node.createInvoice({
			amountMsat,
			description
		});
		return {
			paymentHash: invoice.paymentHash,
			paymentSecret: invoice.paymentSecret
		};
	};

	/**
	 * Alice sends one HTLC of `invoice` over her asset channel `channelId`:
	 * it carries the units Bob is to forward `valueMsat` for, and his fee,
	 * and declares `totalMsat` when that is given (a part). The onion names
	 * Bob's channel with Carol as his next hop, or `next`. Returns what the
	 * send threw.
	 */
	const sendUnits = (
		w: IPayerWorld,
		invoice: IInvoice,
		channelId: Buffer,
		valueMsat: bigint,
		options: { totalMsat?: bigint; next?: Buffer } = {}
	): unknown => {
		const { alice, bob, carol } = w.hosts;
		const units = valueMsat / MSAT_PER_UNIT + FEE_UNITS;
		const alias = bob.node.getChannelManager().getChannel(w.out)!.getFullState()
			.scidAlias!;
		try {
			alice.node.sendPaymentToRoute(
				{
					hops: [
						{
							pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
							shortChannelId: Buffer.alloc(8, 9),
							amountToForwardMsat: units * MSAT_PER_UNIT,
							outgoingCltvValue: 100
						},
						{
							pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
							shortChannelId: Buffer.from(options.next ?? alias),
							amountToForwardMsat: valueMsat,
							outgoingCltvValue: 60
						}
					]
				},
				invoice.paymentHash,
				40,
				invoice.paymentSecret,
				options.totalMsat,
				undefined,
				undefined,
				undefined,
				{
					assetPayment: {
						channelId,
						wireAmountMsat: CARRIER_MSAT,
						customRecords: amountRecord(units)
					}
				}
			);
		} catch (err) {
			return err;
		}
		return undefined;
	};

	/** The asset HTLCs a host has in flight on one of Alice's channels. */
	const assetHtlcsOn = (host: IAssetHost, channelId: Buffer): number =>
		host.node.getAuxiliaryChannelInfo(channelId)!.htlcs.length;

	/** The HTLCs of a hash Bob's channel with Carol holds, at either end. */
	const outHtlcsOf = (w: IPayerWorld, paymentHash: Buffer): number =>
		[w.hosts.bob, w.hosts.carol]
			.map((host) => [
				...(host.node.getChannelManager().getChannel(w.out)?.getFullState()
					.htlcs ?? new Map())
			])
			.flat()
			.filter(([, entry]) => entry.paymentHash.equals(paymentHash)).length;

	const unitsOf = (host: IAssetHost, channelId: Buffer): bigint =>
		host.node.getAuxiliaryChannelInfo(channelId)!.localAssetBalance;

	const carolPaid = (w: IPayerWorld, invoice: IInvoice): boolean => {
		const record = w.hosts.carol.node.getPayment(invoice.paymentHash);
		return (
			record?.direction === PaymentDirection.INCOMING &&
			record.status === PaymentStatus.COMPLETED
		);
	};

	/**
	 * Stop Alice and start the released build over her database, with the
	 * same seed and the reference provider, and her host no longer opted in;
	 * then she and Bob reestablish.
	 */
	const downgrade = async (w: IPayerWorld): Promise<void> => {
		const build = released();
		cut(w);
		w.hosts.alice.node.destroy();
		w.hosts.alice.storage?.close();
		const alice = assetHost(w.tag, 1, aliceHooks(w, false), {
			sqlitePath: w.alicePath,
			build
		});
		made.push(alice);
		w.hosts.alice = alice;
		expect(alice.node, 'Alice runs the released build').to.be.instanceOf(
			build.LightningNode
		);
		listenAlice(w);
		wire(w, 'alice');
		await turns(20);
		await reconnect(w);
	};

	/** Every HTLC of the payment ended in its channel, and the units are what was paid. */
	const nothingLost = (
		w: IPayerWorld,
		invoice: IInvoice,
		paid: { first: bigint; second: bigint }
	): void => {
		for (const [name, channelId] of [
			['first', w.first],
			['second', w.second]
		] as const) {
			expect(
				assetHtlcsOn(w.hosts.alice, channelId),
				`Alice has no HTLC left on her ${name} channel`
			).to.equal(0);
			expect(
				assetHtlcsOn(w.hosts.bob, channelId),
				`Bob has no HTLC left on Alice's ${name} channel`
			).to.equal(0);
			expect(
				unitsOf(w.hosts.alice, channelId),
				`Alice's units on her ${name} channel`
			).to.equal(ALICE_UNITS - paid[name]);
			expect(
				unitsOf(w.hosts.bob, channelId),
				`Bob's units on Alice's ${name} channel`
			).to.equal(BOB_UNITS + paid[name]);
		}
		expect(
			outHtlcsOf(w, invoice.paymentHash),
			"no HTLC is left on Bob's channel with Carol"
		).to.equal(0);
		expect(carolPaid(w, invoice), "Carol's invoice is paid").to.equal(true);
	};

	it('two parts out over two channels, one of them sent again after it failed: 0.44.0 completes the payment on the fulfils Bob sends again, and nothing is lost', async () => {
		const w = await openWorld('send-parts-downgrade');
		const invoice = invoiceOf(w, 5_000_000n, 'paid in two parts');
		const hex = invoice.paymentHash.toString('hex');
		const totalMsat = 5_000_000n;

		// The first part, over the first channel: 3,000 sats at Carol.
		expect(
			sendUnits(w, invoice, w.first, 3_000_000n, { totalMsat }),
			'the first part is sent'
		).to.equal(undefined);
		await turns(50);
		expect(assetHtlcsOn(w.hosts.alice, w.first)).to.equal(1);

		// The second, over the second channel, names a next hop Bob does not
		// have: he fails it back, and the first stays out.
		expect(
			sendUnits(w, invoice, w.second, 2_000_000n, {
				totalMsat,
				next: NOWHERE
			}),
			'the second part is sent'
		).to.equal(undefined);
		await rounds(
			'the second part fails back',
			() => assetHtlcsOn(w.hosts.alice, w.second) === 0
		);
		expect(
			w.hosts.alice.node.getPayment(invoice.paymentHash)?.status,
			'the payment waits on its first part'
		).to.equal(PaymentStatus.PENDING);
		expect(w.failed, 'no payment:failed while a part is out').to.not.include(
			hex
		);

		// Sent again over the second channel, the set is whole at Carol, who
		// settles it. The fulfils Bob then sends Alice are lost.
		w.link.loseFulfils = true;
		expect(
			sendUnits(w, invoice, w.second, 2_000_000n, { totalMsat }),
			'the second part is sent again'
		).to.equal(undefined);
		await rounds('Carol settles the set', () => carolPaid(w, invoice));
		await turns(50);
		expect(w.link.up, "a fulfil of Bob's to Alice was lost").to.equal(false);
		expect(
			w.hosts.alice.node.getPayment(invoice.paymentHash)?.status,
			'Alice stops with the payment out'
		).to.equal(PaymentStatus.PENDING);
		expect(
			w.hosts.alice.node.getPayment(invoice.paymentHash)?.metadata
				?._auxiliaryChannelId,
			"the record names the first part's channel, as an earlier build reads it"
		).to.equal(w.first.toString('hex'));
		expect(assetHtlcsOn(w.hosts.alice, w.first)).to.equal(1);
		expect(assetHtlcsOn(w.hosts.alice, w.second)).to.equal(1);
		const listed = w.hosts.alice.node.getAuxiliaryPaymentHtlcs(
			invoice.paymentHash
		);
		expect(
			listed.map((htlc) => [htlc.channelId.toString('hex'), htlc.amountMsat])
		).to.deep.equal([
			[w.first.toString('hex'), 3_000_000n],
			[w.second.toString('hex'), 2_000_000n],
			[w.second.toString('hex'), 2_000_000n]
		]);

		await downgrade(w);
		await rounds(
			'0.44.0 completes the payment',
			() =>
				w.hosts.alice.node.getPayment(invoice.paymentHash)?.status ===
				PaymentStatus.COMPLETED
		);
		const record = w.hosts.alice.node.getPayment(invoice.paymentHash)!;
		expect(sha256(record.preimage!).equals(invoice.paymentHash)).to.equal(true);
		expect(w.sent, 'payment:sent').to.include(hex);
		nothingLost(w, invoice, {
			first: 3_000n + FEE_UNITS,
			second: 2_000n + FEE_UNITS
		});
		expect(
			[
				...new Set(
					w.outcomes
						.filter((outcome) => outcome.outcome === 'fulfilled')
						.map((outcome) => `${outcome.channelId}:${outcome.htlcId}`)
				)
			].sort(),
			"Alice's host is told of the fulfil of each part that was out"
		).to.deep.equal(
			listed
				.filter((_htlc, index) => index !== 1)
				.map((htlc) => `${htlc.channelId.toString('hex')}:${htlc.htlcId}`)
				.sort()
		);
	});

	it('one HTLC out from a payer with the opt-in: 0.44.0 completes the payment on the fulfil Bob sends again, and nothing is lost', async () => {
		const w = await openWorld('send-one-downgrade');
		const invoice = invoiceOf(w, 3_000_000n, 'paid by one HTLC');
		const hex = invoice.paymentHash.toString('hex');
		w.link.loseFulfils = true;
		expect(
			sendUnits(w, invoice, w.first, 3_000_000n),
			'the payment is sent'
		).to.equal(undefined);
		await rounds('Carol settles the payment', () => carolPaid(w, invoice));
		await turns(50);
		expect(w.link.up, "Bob's fulfil to Alice was lost").to.equal(false);
		expect(
			w.hosts.alice.node.getPayment(invoice.paymentHash)?.status,
			'Alice stops with the payment out'
		).to.equal(PaymentStatus.PENDING);
		expect(
			w.hosts.alice.node.getPayment(invoice.paymentHash)?.metadata
				?._auxiliaryChannelId,
			'the record names its channel, as an earlier build reads it'
		).to.equal(w.first.toString('hex'));
		expect(assetHtlcsOn(w.hosts.alice, w.first)).to.equal(1);

		await downgrade(w);
		await rounds(
			'0.44.0 completes the payment',
			() =>
				w.hosts.alice.node.getPayment(invoice.paymentHash)?.status ===
				PaymentStatus.COMPLETED
		);
		expect(w.sent, 'payment:sent').to.include(hex);
		expect(w.failed, 'payment:failed').to.not.include(hex);
		nothingLost(w, invoice, { first: 3_000n + FEE_UNITS, second: 0n });
		expect(
			[
				...new Set(
					w.outcomes
						.filter((outcome) => outcome.outcome === 'fulfilled')
						.map((outcome) => `${outcome.channelId}:${outcome.htlcId}`)
				)
			],
			"Alice's host is told of the fulfil"
		).to.deep.equal([`${w.first.toString('hex')}:0`]);
	});
});
