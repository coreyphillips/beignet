/**
 * Issue #2093, step 9: the cooperative close of an asset channel.
 *
 * An asset channel closes with the shutdown and closing_signed exchange of
 * a simple taproot channel. Its provider names the script each side closes
 * to and the records that travel beside it, and lays the asset outputs over
 * the payouts. The transaction is signed under the funding key that commits
 * to the asset root, which is the key on chain, and it confirms. Every flow
 * here runs between nodes that store their channels in SQLite, and every
 * closing transaction is put to a chain that reads the funding key from the
 * funding output it holds.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import {
	AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM,
	MAX_AUXILIARY_CLOSE_CANDIDATES,
	recordAuxiliaryClose
} from '../../src/lightning/channel/auxiliary-close';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import {
	ChannelActionType,
	ChannelErrorCode
} from '../../src/lightning/channel/channel-actions';
import type { ChannelAction } from '../../src/lightning/channel/channel-actions';
import { ChannelState } from '../../src/lightning/channel/types';
import { CommitmentType } from '../../src/lightning/chain/types';
import {
	decodeClosingSignedMessage,
	decodeShutdownMessage,
	encodeShutdownMessage
} from '../../src/lightning/message/channel-close';
import { MessageType } from '../../src/lightning/message/types';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import { TestChain } from './helpers/auxiliary-chain';
import {
	amountRecord,
	leafFor,
	referenceProvider
} from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';
import { writableState } from './helpers/writable-state';

const settle = async (): Promise<void> => {
	for (let i = 0; i < 40; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/** What a wallet would ask to be paid to. The provider names its own script. */
const DESTINATION = Buffer.from('0014' + '11'.repeat(20), 'hex');

type Hooks = Partial<IAuxiliaryChannelConfig>;
type Provider = IChannelAuxiliaryProvider;

/** The script the reference provider closes a party's units to. */
const assetCloseScript = (fundingPubkey: Buffer, units: bigint): Buffer =>
	bitcoin.payments.p2tr({
		internalPubkey: fundingPubkey.subarray(1),
		scriptTree: { output: leafFor(`close:${units}`).script }
	}).output!;

/** The script the reference provider closes a party's bitcoin to. */
const bitcoinCloseScript = (fundingPubkey: Buffer): Buffer =>
	bitcoin.payments.p2tr({ internalPubkey: fundingPubkey.subarray(1) }).output!;

/**
 * The reference provider with the layout a provider of real assets uses:
 * each party's units ride an output of their own beside its bitcoin, and
 * the whole layout is the provider's.
 */
function withSeparateAnchors(provider: Provider): Provider {
	return {
		...provider,
		extraCloseOutputScriptLengths: (state) =>
			[state.auxiliaryState!.localBalance, state.auxiliaryState!.remoteBalance]
				.filter((units) => units > 0n)
				.map(() => 34),
		buildClose(context) {
			const auxiliary = context.state.auxiliaryState!;
			const outputs: Array<{
				value: bigint;
				script: Buffer;
				side: 'local' | 'remote';
				asset: boolean;
			}> = [];
			for (const [side, amount, units, records, script, dust] of [
				[
					'local',
					context.localAmount,
					auxiliary.localBalance,
					auxiliary.localShutdownRecords,
					context.state.localShutdownScript,
					context.localDustLimit
				],
				[
					'remote',
					context.remoteAmount,
					auxiliary.remoteBalance,
					auxiliary.remoteShutdownRecords,
					context.state.remoteShutdownScript,
					context.remoteDustLimit
				]
			] as const) {
				if (units > 0n) {
					const anchor = bitcoin.payments.p2tr({
						internalPubkey: records!.get(65539n)!.subarray(1),
						scriptTree: { output: leafFor(`anchor:${units}`).script }
					}).output!;
					const rest = amount - AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM;
					if (rest > dust) {
						outputs.push(
							{
								value: AUXILIARY_CLOSE_ASSET_OUTPUT_MINIMUM,
								script: anchor,
								side,
								asset: true
							},
							{ value: rest, script: script!, side, asset: false }
						);
					} else {
						outputs.push({ value: amount, script: anchor, side, asset: true });
					}
				} else if (amount > dust) {
					outputs.push({ value: amount, script: script!, side, asset: false });
				}
			}
			// Both peers arrive at one order on their own.
			outputs.sort((a, b) =>
				a.value !== b.value
					? a.value < b.value
						? -1
						: 1
					: a.script.compare(b.script)
			);
			return {
				outputs,
				outputScripts: new Map(),
				customData: Buffer.from('split close assets')
			};
		}
	};
}

describe('the cooperative close of an asset channel (issue #2093)', function () {
	this.timeout(60_000);
	withAssetOpens();

	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) host.node.destroy();
	});

	interface IPair {
		alice: IAssetHost;
		bob: IAssetHost;
		channelId: Buffer;
		hex: string;
		chain: TestChain;
		funding: bitcoin.Transaction;
		/** Every message either node sent. */
		wire: Array<{ from: 'alice' | 'bob'; type: number; payload: Buffer }>;
		/** Every transaction a node handed its host to publish, after the funding. */
		published: { alice: string[]; bob: string[] };
	}

	/** Alice opens an asset channel to Bob: 9000 and 1000 units, on SQLite. */
	async function pair(
		tag: string,
		options: { alice?: Hooks; bob?: Hooks } = {}
	): Promise<IPair> {
		const alice = assetHost(tag, 1, options.alice ?? {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{
				valueIncomingHtlc: (context) =>
					context.auxiliaryAmount === undefined
						? undefined
						: context.auxiliaryAmount * 1000n,
				...options.bob
			},
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		// The funding transaction the opener published is what is on chain.
		expect(alice.broadcasts).to.have.length(1);
		const funding = bitcoin.Transaction.fromHex(alice.broadcasts[0]);
		const chain = new TestChain();
		chain.seed(funding);
		const wire: IPair['wire'] = [];
		const published: IPair['published'] = { alice: [], bob: [] };
		for (const [from, host] of [
			['alice', alice],
			['bob', bob]
		] as const) {
			host.node.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					wire.push({ from, type, payload });
				}
			);
			host.node.on('broadcast:tx', (tx: Buffer) => {
				published[from].push(tx.toString('hex'));
			});
		}
		return {
			alice,
			bob,
			channelId,
			hex: channelId.toString('hex'),
			chain,
			funding,
			wire,
			published
		};
	}

	const channelOf = (host: IAssetHost, channelId: Buffer) =>
		host.node.getChannelManager().getChannel(channelId)!;
	const stateOf = (host: IAssetHost, channelId: Buffer) =>
		channelOf(host, channelId).getFullState();
	const errorsOf = (host: IAssetHost): string[] =>
		host.errors.filter(
			(error) =>
				!error.startsWith('AUTO_FUNDING_FAILED') &&
				!error.startsWith('NO_ROUTING_HINTS')
		);
	const sentTypes = (made: IPair, from?: 'alice' | 'bob'): number[] =>
		made.wire
			.filter((message) => from === undefined || message.from === from)
			.map((message) => message.type);
	/** The peers `host` asks its carrier to drop the connection of, from now on. */
	const dropsOf = (host: IAssetHost): string[] => {
		const dropped: string[] = [];
		host.node.on('peer:disconnect-requested', (peer: string) => {
			dropped.push(peer);
		});
		return dropped;
	};
	const storedRow = (host: IAssetHost, hex: string): string =>
		JSON.stringify(
			serializeChannelState(host.storage!.loadChannel(hex)!.state)
		);

	/** Alice pays `units` to a hold invoice of Bob: the HTLC stays in flight. */
	function payHeld(made: IPair, units: bigint): Buffer {
		const { alice, bob, channelId } = made;
		const invoice = bob.node.createInvoice({
			amountMsat: units * 1000n,
			description: 'held',
			hold: true
		});
		alice.node.sendPaymentToRoute(
			{
				hops: [
					{
						pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
						shortChannelId: Buffer.alloc(8, 9),
						amountToForwardMsat: units * 1000n,
						outgoingCltvValue: 40
					}
				]
			},
			invoice.paymentHash,
			40,
			invoice.paymentSecret,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				assetPayment: {
					channelId,
					wireAmountMsat: 354_000n,
					customRecords: amountRecord(units)
				}
			}
		);
		return invoice.paymentHash;
	}

	/**
	 * Close the channel from one side, with or without an HTLC that has to
	 * drain first, put the transaction on chain and tell both nodes.
	 */
	async function closesOnChain(
		tag: string,
		options: {
			closer: 'opener' | 'acceptor';
			drain?: boolean;
			separate?: boolean;
		}
	): Promise<void> {
		const provider = (): Hooks =>
			options.separate
				? { provider: withSeparateAnchors(referenceProvider()) }
				: {};
		const made = await pair(tag, { alice: provider(), bob: provider() });
		const { alice, bob, channelId, hex, chain, funding, wire } = made;
		const closer = options.closer === 'opener' ? alice : bob;
		const aliceKey = stateOf(alice, channelId).localBasepoints.fundingPubkey;
		const bobKey = stateOf(bob, channelId).localBasepoints.fundingPubkey;

		let held: Buffer | undefined;
		if (options.drain) {
			held = payHeld(made, 5000n);
			await settle();
			for (const host of [alice, bob]) {
				expect(
					host.node.getAuxiliaryChannelInfo(channelId)!.htlcs
				).to.have.length(1);
			}
		}
		const units: [bigint, bigint] = options.drain
			? [4000n, 6000n]
			: [9000n, 1000n];
		const sats: [number, number] = options.drain
			? [1_500_000 - 354, 500_000 + 354]
			: [1_500_000, 500_000];

		const closed = closer.node.closeChannel(channelId, DESTINATION);
		expect(closed, JSON.stringify(closed)).to.deep.equal({ ok: true });
		await settle();

		if (options.drain) {
			// Both shutdowns are out, and nothing is signed while the HTLC is in
			// flight.
			for (const host of [alice, bob]) {
				expect(stateOf(host, channelId).state).to.equal(
					ChannelState.SHUTTING_DOWN
				);
			}
			expect(sentTypes(made)).to.not.include(MessageType.CLOSING_SIGNED);
			expect(alice.broadcasts).to.have.length(1);
			expect(made.published.alice.concat(made.published.bob)).to.deep.equal([]);
			expect(bob.node.settleHeldHtlc(held!)).to.equal(true);
			await settle();
		}
		expect(errorsOf(alice)).to.deep.equal([]);
		expect(errorsOf(bob)).to.deep.equal([]);

		// Each shutdown carries the script its sender's provider named and
		// the provider's record beside it, and no script anyone else chose.
		const shutdowns = wire.filter(
			(message) => message.type === MessageType.SHUTDOWN
		);
		expect(shutdowns.map((message) => message.from).sort()).to.deep.equal([
			'alice',
			'bob'
		]);
		for (const message of shutdowns) {
			const key = message.from === 'alice' ? aliceKey : bobKey;
			const read = decodeShutdownMessage(message.payload, {
				customRecords: true
			});
			expect(read.scriptPubkey.equals(bitcoinCloseScript(key))).to.equal(true);
			expect([...read.customRecords!.keys()]).to.deep.equal([65539n]);
			expect(read.customRecords!.get(65539n)!.equals(key)).to.equal(true);
			expect(read.shutdownNonce).to.have.length(66);
		}

		// One closing_signed each way, and both nodes publish one transaction.
		expect(
			wire
				.filter((message) => message.type === MessageType.CLOSING_SIGNED)
				.map((message) => message.from)
				.sort()
		).to.deep.equal(['alice', 'bob']);
		expect(made.published.alice).to.have.length(1);
		expect(made.published.bob).to.have.length(1);
		expect(made.published.alice[0]).to.equal(made.published.bob[0]);
		const tx = bitcoin.Transaction.fromHex(made.published.bob[0]);
		const txid = tx.getId();
		expect(tx.ins).to.have.length(1);
		expect(Buffer.from(tx.ins[0].hash).reverse().toString('hex')).to.equal(
			funding.getId()
		);
		expect(tx.ins[0].index).to.equal(1);

		// Before the transaction is anywhere but in these two nodes, each has
		// it and the provider's payload for it in its row.
		const payload = options.separate
			? 'split close assets'
			: 'signed close assets';
		for (const host of [alice, bob]) {
			const live = stateOf(host, channelId);
			expect(live.state).to.equal(ChannelState.CLOSED);
			const row = host.storage!.loadChannel(hex)!.state;
			expect(row.state).to.equal(ChannelState.CLOSED);
			expect(row.lastCooperativeCloseTxHex).to.equal(tx.toHex());
			for (const state of [live, row]) {
				const auxiliary = state.auxiliaryState!;
				expect([...auxiliary.closeTransactions!.keys()]).to.deep.equal([txid]);
				expect(auxiliary.closeTransactions!.get(txid)!.toString()).to.equal(
					payload
				);
				expect([auxiliary.localBalance, auxiliary.remoteBalance]).to.deep.equal(
					host === alice ? units : [units[1], units[0]]
				);
			}
			// What the row reads back is what the channel holds: the records
			// of both shutdowns and the close this node accepted.
			const kept = live.auxiliaryState!;
			const read = row.auxiliaryState!;
			for (const field of [
				'localShutdownRecords',
				'remoteShutdownRecords'
			] as const) {
				expect([...read[field]!.keys()]).to.deep.equal([65539n]);
				expect(
					read[field]!.get(65539n)!.equals(kept[field]!.get(65539n)!)
				).to.equal(true);
			}
			expect(
				read
					.localShutdownRecords!.get(65539n)!
					.equals(host === alice ? aliceKey : bobKey)
			).to.equal(true);
			expect(
				read
					.remoteShutdownRecords!.get(65539n)!
					.equals(host === alice ? bobKey : aliceKey)
			).to.equal(true);
			expect(
				read.acceptedClosingSigned!.equals(kept.acceptedClosingSigned!)
			).to.equal(true);
		}

		// The chain takes it: the signature is of the key in the funding
		// output, the fee relays and no output is dust.
		const { fee, vsize } = chain.accept(tx);
		expect(fee).to.be.at.least(vsize);
		const paid = (script: Buffer): number[] =>
			tx.outs
				.filter((out) => out.script.equals(script))
				.map((out) => out.value);
		if (options.separate) {
			// Each party's units ride a 330 sat output of their own, and the
			// rest of its bitcoin goes to the script its shutdown named. The
			// opener pays the fee.
			expect(tx.outs).to.have.length(4);
			for (const [key, amount, sat, pays] of [
				[aliceKey, units[0], sats[0], true],
				[bobKey, units[1], sats[1], false]
			] as const) {
				expect(
					paid(
						bitcoin.payments.p2tr({
							internalPubkey: key.subarray(1),
							scriptTree: { output: leafFor(`anchor:${amount}`).script }
						}).output!
					)
				).to.deep.equal([330]);
				expect(paid(bitcoinCloseScript(key))).to.deep.equal([
					sat - 330 - (pays ? fee : 0)
				]);
			}
		} else {
			// The assets are on chain where the provider said: each party's
			// output commits to its units, and holds its bitcoin.
			expect(tx.outs).to.have.length(2);
			expect(paid(assetCloseScript(aliceKey, units[0]))).to.deep.equal([
				sats[0] - fee
			]);
			expect(paid(assetCloseScript(bobKey, units[1]))).to.deep.equal([sats[1]]);
		}

		const height = chain.mine(tx);
		expect(chain.spender(funding.getId(), 1)).to.equal(txid);
		for (const host of [alice, bob]) {
			host.node.handleFundingSpent(channelId, tx, height, DESTINATION);
			host.node.handleNewBlock(height);
		}
		await settle();
		for (const host of [alice, bob]) {
			expect(errorsOf(host)).to.deep.equal([]);
			// What a host reads to bring the assets of the close into its own
			// books: the spend of the funding output, as a copy, and the
			// provider's payload for that transaction in the channel's row.
			const monitor = host.node.getChannelMonitorState(channelId)!;
			const broadcast = monitor.commitmentBroadcast!;
			expect(broadcast.commitmentType).to.equal(
				CommitmentType.COOPERATIVE_CLOSE
			);
			expect(broadcast.txid).to.equal(txid);
			expect(
				stateOf(host, channelId).auxiliaryState!.closeTransactions!.has(txid)
			).to.equal(true);
			broadcast.txid = 'changed by the reader';
			expect(
				host.node.getChannelMonitorState(channelId)!.commitmentBroadcast!.txid
			).to.equal(txid);
			expect(host.node.getChannelMonitorState(Buffer.alloc(32, 9))).to.equal(
				undefined
			);
			expect(() => host.node.getChannelMonitorState(Buffer.alloc(31))).to.throw(
				'channelId must be a 32-byte Buffer'
			);
			expect(stateOf(host, channelId).state).to.equal(ChannelState.CLOSED);
		}
		// A node that sees the close again signs nothing and publishes nothing.
		expect(made.published.alice).to.have.length(1);
		expect(made.published.bob).to.have.length(1);
	}

	describe('confirms, with the assets where the provider said', () => {
		for (const closer of ['opener', 'acceptor'] as const) {
			it(`closed by the ${closer}`, async () => {
				await closesOnChain(`aux-close-${closer}`, { closer });
			});
			it(`closed by the ${closer} with an asset HTLC that drains first`, async () => {
				await closesOnChain(`aux-close-drain-${closer}`, {
					closer,
					drain: true
				});
			});
			it(`closed by the ${closer}, the units on outputs of their own`, async () => {
				await closesOnChain(`aux-close-split-${closer}`, {
					closer,
					separate: true
				});
			});
		}
		it('closed by the acceptor after a drain, the units on outputs of their own', async () => {
			await closesOnChain('aux-close-split-drain', {
				closer: 'acceptor',
				drain: true,
				separate: true
			});
		});
	});

	describe('a signature under the unrooted funding key', () => {
		it('is not what the close carries, and would not confirm', async () => {
			const made = await pair('aux-close-rooted');
			const { alice, channelId, chain } = made;
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			const tx = bitcoin.Transaction.fromHex(made.published.bob[0]);
			chain.accept(tx);
			// The same transaction over a funding output of the bare aggregate
			// key, which is what an ordinary taproot channel would have: the
			// chain refuses the signature.
			const state = stateOf(alice, channelId);
			const { createTaprootFundingScript } =
				require('../../src/lightning/script/funding-taproot') as typeof import('../../src/lightning/script/funding-taproot');
			const bare = createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints!.fundingPubkey
			).p2trOutput;
			expect(bare.equals(made.funding.outs[1].script)).to.equal(false);
			const unrooted = new TestChain();
			const other = new bitcoin.Transaction();
			other.version = 2;
			other.addInput(Buffer.alloc(32, 3), 0);
			other.addOutput(Buffer.from('6a', 'hex'), 0);
			other.addOutput(bare, made.funding.outs[1].value);
			unrooted.seed(other);
			const respent = bitcoin.Transaction.fromBuffer(tx.toBuffer());
			respent.ins[0].hash = Buffer.from(other.getId(), 'hex').reverse();
			expect(() => unrooted.accept(respent)).to.throw(
				'input 0 is not signed by the key of the output it spends'
			);
		});
	});

	describe('a provider that cannot answer refuses by name, before anything is sent or stored', () => {
		const refused = (hex: string, operation: string, cause: string): string =>
			`The asset provider refused ${operation} (channel ${hex}): ${cause}`;

		it('at the shutdown this node starts', async () => {
			const made = await pair('aux-close-refuse-own', {
				alice: {
					provider: {
						...referenceProvider(),
						prepareShutdown: () => {
							throw new Error('no destination yet');
						}
					}
				}
			});
			const { alice, bob, channelId, hex } = made;
			const before = storedRow(alice, hex);
			const drops = dropsOf(alice);
			const closed = alice.node.closeChannel(channelId, DESTINATION);
			await settle();
			// The operator is told directly, and the peer waits for nothing:
			// the connection stays.
			expect(drops).to.deep.equal([]);
			expect(closed).to.deep.equal({
				ok: false,
				error: refused(hex, 'a shutdown', 'no destination yet'),
				code: ChannelErrorCode.ASSET_PROVIDER_REFUSED
			});
			expect(sentTypes(made)).to.deep.equal([]);
			expect(storedRow(alice, hex)).to.equal(before);
			for (const host of [alice, bob]) {
				expect(stateOf(host, channelId).state).to.equal(ChannelState.NORMAL);
			}
			expect(stateOf(alice, channelId).localShutdownScript).to.equal(null);
		});

		it('at the answer to the shutdown of the peer', async () => {
			const made = await pair('aux-close-refuse-answer', {
				bob: {
					provider: {
						...referenceProvider(),
						prepareShutdown: () => {
							throw new Error('no destination yet');
						}
					}
				}
			});
			const { alice, bob, channelId, hex } = made;
			const before = storedRow(bob, hex);
			const drops = dropsOf(bob);
			const errors: string[] = [];
			bob.node
				.getChannelManager()
				.on('error', (_id: unknown, message: unknown) => {
					errors.push(String(message));
				});
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			expect(errors).to.deep.equal([
				refused(hex, 'a shutdown', 'no destination yet')
			]);
			// The connection is dropped: the next one has the peer ask again.
			expect(drops).to.deep.equal([alice.node.getNodeId()]);
			// The peer is told nothing and the channel is not failed for it.
			expect(sentTypes(made, 'bob')).to.deep.equal([]);
			expect(stateOf(bob, channelId).state).to.equal(
				ChannelState.AWAITING_REESTABLISH
			);
			expect(storedRow(bob, hex)).to.equal(before);
			expect(
				stateOf(bob, channelId).auxiliaryState!.remoteShutdownRecords
			).to.equal(undefined);
		});

		it("at the judging of the shutdown of the peer, where a throw is this node's and a no is the peer's", async () => {
			for (const [answer, expectation] of [
				['throws', 'local'],
				['says no', 'wire']
			] as const) {
				const made = await pair(`aux-close-refuse-verify-${expectation}`, {
					bob: {
						provider: {
							...referenceProvider(),
							verifyShutdown: () => {
								if (answer === 'throws') throw new Error('proofs unavailable');
								return false;
							}
						}
					}
				});
				const { alice, bob, channelId, hex } = made;
				const drops = dropsOf(bob);
				const errors: string[] = [];
				bob.node
					.getChannelManager()
					.on('error', (_id: unknown, message: unknown) => {
						errors.push(String(message));
					});
				expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
					ok: true
				});
				await settle();
				if (expectation === 'local') {
					expect(errors).to.deep.equal([
						refused(hex, 'a shutdown', 'proofs unavailable')
					]);
					expect(drops).to.deep.equal([alice.node.getNodeId()]);
					expect(sentTypes(made, 'bob')).to.deep.equal([]);
					expect(stateOf(bob, channelId).state).to.equal(
						ChannelState.AWAITING_REESTABLISH
					);
				} else {
					expect(errors.join('; ')).to.include(
						'Invalid asset shutdown descriptor'
					);
					expect(sentTypes(made, 'bob')).to.include(MessageType.ERROR);
				}
				expect(sentTypes(made)).to.not.include(MessageType.CLOSING_SIGNED);
				expect(
					stateOf(bob, channelId).auxiliaryState!.remoteShutdownRecords
				).to.equal(undefined);
			}
		});

		for (const who of ['proposer', 'responder'] as const) {
			it(`at the building of the close, on the ${who}`, async () => {
				const failing = (): Hooks => ({
					provider: {
						...referenceProvider(),
						buildClose: () => {
							throw new Error('no proof for the close');
						}
					}
				});
				const made = await pair(`aux-close-refuse-build-${who}`, {
					alice: who === 'proposer' ? failing() : {},
					bob: who === 'responder' ? failing() : {}
				});
				const { alice, bob, channelId, hex } = made;
				const host = who === 'proposer' ? alice : bob;
				const drops = dropsOf(host);
				const errors: string[] = [];
				host.node
					.getChannelManager()
					.on('error', (_id: unknown, message: unknown) => {
						errors.push(String(message));
					});
				// The opener proposes, so Alice is the proposer whoever closes.
				expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
					ok: true
				});
				await settle();
				expect(errors).to.deep.equal([
					refused(hex, 'a cooperative close', 'no proof for the close')
				]);
				expect(drops).to.deep.equal([
					(host === alice ? bob : alice).node.getNodeId()
				]);
				// The shutdowns went, and then: the proposer sent no offer, or
				// the responder answered the offer with nothing at all.
				expect([...sentTypes(made)].sort((a, b) => a - b)).to.deep.equal(
					who === 'proposer'
						? [MessageType.SHUTDOWN, MessageType.SHUTDOWN]
						: [
								MessageType.SHUTDOWN,
								MessageType.SHUTDOWN,
								MessageType.CLOSING_SIGNED
						  ]
				);
				expect(
					sentTypes(made, host === alice ? 'alice' : 'bob')
				).to.not.include(MessageType.ERROR);
				expect(stateOf(host, channelId).state).to.equal(
					ChannelState.AWAITING_REESTABLISH
				);
				expect(
					stateOf(host, channelId).auxiliaryState!.closeTransactions
				).to.equal(undefined);
				expect(
					host.storage!.loadChannel(hex)!.state.auxiliaryState!
						.closeTransactions
				).to.equal(undefined);
				// Nothing but the funding was ever published.
				expect(alice.broadcasts).to.have.length(1);
				expect(made.published.alice.concat(made.published.bob)).to.deep.equal(
					[]
				);
			});
		}
	});

	describe('a provider answer that would lose funds is refused before anything is signed', () => {
		const cases: Array<[string, (provider: Provider) => Provider, string]> = [
			[
				'a party with units paid less than its bitcoin',
				(provider) => {
					const split = withSeparateAnchors(provider);
					return {
						...split,
						buildClose(context) {
							const result = split.buildClose(context);
							const outputs = result.outputs!.map((output) => ({ ...output }));
							outputs.find(
								(output) => output.side === 'local' && !output.asset
							)!.value -= 1n;
							return { ...result, outputs };
						}
					};
				},
				'Asset close payout would lose funds'
			],
			[
				'a party with units and no asset output',
				(provider) => {
					const split = withSeparateAnchors(provider);
					return {
						...split,
						buildClose(context) {
							const result = split.buildClose(context);
							return {
								...result,
								outputs: result.outputs!.map((output) => ({
									...output,
									asset: false
								}))
							};
						}
					};
				},
				'Asset close payout would lose funds'
			],
			[
				'a payout to a script that is not taproot',
				(provider) => {
					const split = withSeparateAnchors(provider);
					return {
						...split,
						buildClose(context) {
							const result = split.buildClose(context);
							const outputs = result.outputs!.map((output) => ({ ...output }));
							outputs[outputs.length - 1].script = DESTINATION;
							return { ...result, outputs };
						}
					};
				},
				'Invalid asset close payout'
			],
			[
				'units left on an output the provider did not commit',
				(provider) => ({
					...provider,
					buildClose: () => ({
						outputScripts: new Map(),
						customData: Buffer.from('nothing committed')
					})
				}),
				'Missing asset close commitment'
			],
			[
				'no payload for the close',
				(provider) => ({
					...provider,
					buildClose: (context) => ({
						...provider.buildClose(context),
						customData: 'not bytes' as unknown as Buffer
					})
				}),
				'Invalid asset close answer'
			],
			[
				'more outputs than a close may add',
				(provider) => ({
					...provider,
					extraCloseOutputScriptLengths: () => new Array(63).fill(34)
				}),
				'Invalid auxiliary close shape'
			]
		];
		for (const [what, wrap, cause] of cases) {
			it(what, async () => {
				const made = await pair(
					`aux-close-bad-${cases.findIndex(([name]) => name === what)}`,
					{
						alice: { provider: wrap(referenceProvider()) }
					}
				);
				const { alice, bob, channelId, hex } = made;
				const drops = dropsOf(alice);
				const errors: string[] = [];
				alice.node
					.getChannelManager()
					.on('error', (_id: unknown, message: unknown) => {
						errors.push(String(message));
					});
				expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
					ok: true
				});
				await settle();
				expect(errors).to.deep.equal([
					`The asset provider refused a cooperative close (channel ${hex}): ${cause}`
				]);
				expect(drops).to.deep.equal([bob.node.getNodeId()]);
				expect(sentTypes(made)).to.not.include(MessageType.CLOSING_SIGNED);
				expect(
					stateOf(alice, channelId).auxiliaryState!.closeTransactions
				).to.equal(undefined);
				expect(alice.broadcasts).to.have.length(1);
				expect(made.published.alice.concat(made.published.bob)).to.deep.equal(
					[]
				);
			});
		}
	});

	describe('what an asset channel signed for a close', () => {
		it('takes the close it accepted once more and signs nothing for it, and nothing else', async () => {
			const made = await pair('aux-close-echo');
			const { alice, bob, channelId, wire } = made;
			expect(alice.node.closeChannel(channelId, DESTINATION)).to.deep.equal({
				ok: true
			});
			await settle();
			const never = (): never => {
				throw new Error('a closed channel must not sign again');
			};
			// Alice accepted Bob's closing_signed; Bob accepted Alice's.
			for (const [host, from] of [
				[alice, 'bob'],
				[bob, 'alice']
			] as const) {
				const accepted = wire.find(
					(message) =>
						message.from === from && message.type === MessageType.CLOSING_SIGNED
				)!;
				const channel = channelOf(host, channelId);
				expect(
					stateOf(
						host,
						channelId
					).auxiliaryState!.acceptedClosingSigned!.equals(accepted.payload)
				).to.equal(true);
				const message = decodeClosingSignedMessage(accepted.payload);
				expect(
					channel.handleClosingSigned(message, never, never)
				).to.deep.equal([]);
				for (const altered of [
					{ ...message, feeSatoshis: message.feeSatoshis + 1n },
					{ ...message, partialSignature: Buffer.alloc(32, 1) }
				]) {
					const actions: ChannelAction[] = channel.handleClosingSigned(
						altered,
						never,
						never
					);
					expect(actions).to.have.length(1);
					expect(actions[0].type).to.equal(ChannelActionType.ERROR);
				}
				expect(stateOf(host, channelId).state).to.equal(ChannelState.CLOSED);
			}
		});

		it('keeps the payload of every transaction it signed, and of no more than it can keep', async () => {
			const made = await pair('aux-close-candidates');
			const { alice, channelId } = made;
			const state = writableState(channelOf(alice, channelId));
			for (let i = 0; i < MAX_AUXILIARY_CLOSE_CANDIDATES; i++) {
				recordAuxiliaryClose(state, `${i}`.padStart(64, '0'), Buffer.from([i]));
			}
			// The same transaction again is the same entry.
			recordAuxiliaryClose(state, '0'.padStart(64, '0'), Buffer.from([9]));
			expect(state.auxiliaryState!.closeTransactions!.size).to.equal(
				MAX_AUXILIARY_CLOSE_CANDIDATES
			);
			expect(() =>
				recordAuxiliaryClose(state, 'f'.repeat(64), Buffer.alloc(1))
			).to.throw('Too many asset closing transactions were signed');
		});
	});

	describe('the shutdown message', () => {
		const channelId = Buffer.alloc(32, 5);
		const scriptPubkey = bitcoinCloseScript(Buffer.alloc(33, 2));
		const shutdownNonce = Buffer.alloc(66, 7);

		it('is the same bytes as before without asset records', () => {
			const plain = encodeShutdownMessage({ channelId, scriptPubkey });
			expect(plain.toString('hex')).to.equal(
				channelId.toString('hex') + '0022' + scriptPubkey.toString('hex')
			);
			expect(
				encodeShutdownMessage({
					channelId,
					scriptPubkey,
					customRecords: new Map()
				}).equals(plain)
			).to.equal(true);
			const withNonce = encodeShutdownMessage({
				channelId,
				scriptPubkey,
				shutdownNonce
			});
			expect(withNonce.toString('hex')).to.equal(
				plain.toString('hex') + '0842' + shutdownNonce.toString('hex')
			);
			// Read as before, with or without the option.
			for (const options of [undefined, { customRecords: true }]) {
				const read = decodeShutdownMessage(withNonce, options);
				expect(read.shutdownNonce!.equals(shutdownNonce)).to.equal(true);
				expect('customRecords' in read).to.equal(false);
			}
		});

		it('carries asset records in type order beside the nonce, read only when asked for', () => {
			const customRecords = new Map([
				[65541n, Buffer.from('later')],
				[65539n, Buffer.alloc(33, 3)]
			]);
			const encoded = encodeShutdownMessage({
				channelId,
				scriptPubkey,
				shutdownNonce,
				customRecords
			});
			const read = decodeShutdownMessage(encoded, { customRecords: true });
			expect(read.scriptPubkey.equals(scriptPubkey)).to.equal(true);
			expect(read.shutdownNonce!.equals(shutdownNonce)).to.equal(true);
			expect([...read.customRecords!.keys()]).to.deep.equal([65539n, 65541n]);
			expect(read.customRecords!.get(65541n)!.toString()).to.equal('later');
			// The standard reader passes odd records by and keeps its rule for
			// an even one it does not know.
			expect('customRecords' in decodeShutdownMessage(encoded)).to.equal(false);
			const even = encodeShutdownMessage({
				channelId,
				scriptPubkey,
				customRecords: new Map([[65540n, Buffer.alloc(1)]])
			});
			expect(() => decodeShutdownMessage(even)).to.throw('65540');
			expect(
				decodeShutdownMessage(even, { customRecords: true }).customRecords!.get(
					65540n
				)!.length
			).to.equal(1);
			// A record below the custom range is not a custom record.
			expect(() =>
				encodeShutdownMessage({
					channelId,
					scriptPubkey,
					customRecords: new Map([[9n, Buffer.alloc(1)]])
				})
			).to.throw('Invalid or reserved Lightning custom record');
		});
	});
});
