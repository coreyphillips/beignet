/**
 * Issue #2098, step 8: the edges of collecting and committing a set of
 * asset parts. A records write that fails reveals nothing and fails the
 * set back; from the write on, nothing gives the set up: a refused fulfil
 * stays owed with its decision, the MPP timer leaves the set alone, a part
 * dispatched again is fulfilled once, and turning the opt-in off changes
 * nothing for it. A set with a part at risk at its completion (a channel
 * on the chain, a fail owed, short fee coins, a circular payment's record)
 * is failed back whole before anything is written. A part that would make
 * the settled row too large for a guardian is refused, and a set that never
 * completes fails back part by part, each fail owed until the provider
 * takes it, the host told of each HTLC.
 *
 * Bitcoin in, asset out, on the chain world of auxiliary-forward-world.ts:
 * Alice pays Carol's ordinary invoice in parts through Bob, whose host makes
 * each part an asset HTLC to Carol.
 *
 * Written first: on the build before step 8, where no set of asset parts
 * is collected, each case fails where the set is first held or committed.
 * The contract is "Before anything is written" and "The commit, and every
 * part claimed" in docs/EXTENSIONS.md.
 */

import { expect } from 'chai';
import { isFixedAssetHtlcChannel } from '../../src/lightning/channel/types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { FAILURE_MESSAGE_LENGTH } from '../../src/lightning/onion/failures';
import { encodedMutationBytes } from '../../src/lightning/recovery/frame-codec';
import type {
	IRecoveryCommitResult,
	RecoveryMutation,
	SafetyTransition
} from '../../src/lightning/recovery/types';
import {
	aliasOf,
	forwardChainWorld,
	partsInvoice,
	payInParts,
	sendPart,
	type IPartsInvoice
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
	withAssetPartsReceived
} from './helpers/auxiliary-nodes';
import { SWEEP_DESTINATION } from './helpers/auxiliary-on-chain';
import {
	alicePaid,
	alicesStatus,
	asksFor,
	carolsRecord,
	claimedByPreimage,
	collected,
	committed,
	decisionOf,
	endsOf,
	expectNothingSettled,
	heldOn,
	hex,
	isSpent,
	keeping,
	keyOf,
	notSettledOf,
	onCommit,
	openReceived,
	receivedEntries,
	receivedOutputs,
	refusing,
	unitsOf,
	UPDATE_FAIL_HTLC,
	UPDATE_FAIL_MALFORMED_HTLC,
	UPDATE_FULFILL_HTLC,
	watchManager,
	wireWatch,
	type Log
} from './helpers/auxiliary-parts-checks';

type Timer = { mppTimeoutMs: number; failTimedOutMppPayments: () => void };

describe('the edges of a set of asset parts (issue #2098, step 8)', function () {
	this.timeout(240_000);
	withAssetOpens();
	withAssetForwards();
	withAssetPartsReceived();
	const world = forwardChainWorld();
	afterEach(() => world.dispose());

	const aliceFailed = (s: IPartsScene, invoice: IPartsInvoice): Promise<void> =>
		rounds(
			'the payment fails at Alice',
			() => alicesStatus(s, invoice) === PaymentStatus.FAILED,
			60
		);
	const retry = (s: IPartsScene): void =>
		(
			s.w.hosts.carol.node as unknown as { retryAuxiliaryOwed: () => void }
		).retryAuxiliaryOwed();
	const timerOf = (s: IPartsScene): Timer =>
		s.w.hosts.carol.node as unknown as Timer;

	/**
	 * Alice sends the first part and Carol holds it in the set; the second
	 * is sent by the test. The invoice asks 5,000,000 of two parts.
	 */
	async function firstHeld(
		s: IPartsScene,
		tag: string
	): Promise<IPartsInvoice> {
		const invoice = partsInvoice(s.w, tag, 5_000_000n);
		sendPart(s.w, invoice, 3_000_000n);
		await rounds(
			'Carol is asked about the first part',
			() => asksFor(s, invoice).length === 1
		);
		await rounds(
			'Carol holds the first part in the set',
			() => collected(s.w.hosts.carol, invoice.paymentHash) === 1
		);
		return invoice;
	}

	/** The set is committed and each part's fulfil refused: each holds its decision. */
	async function committedUnfulfilled(
		s: IPartsScene,
		invoice: IPartsInvoice
	): Promise<ReturnType<typeof receivedEntries>> {
		await committed(s, invoice);
		await turns(50);
		const carol = s.w.hosts.carol;
		const parts = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
		expect(parts.length, 'each fulfil was refused').to.equal(2);
		for (const part of parts) {
			expect(
				decisionOf(carol, s.w.outChannel, part.id),
				'the part keeps its decision'
			).to.equal('settle');
			expect(
				carol.node
					.getChannelManager()
					.owesAuxiliaryRemoval(s.w.outChannel, part.id),
				'its fulfil is owed'
			).to.equal(true);
		}
		return parts;
	}

	/** The provider takes the fulfils again: each part is fulfilled once and never failed. */
	async function fulfilledOnce(
		s: IPartsScene,
		invoice: IPartsInvoice,
		parts: ReturnType<typeof receivedEntries>,
		sent: string[],
		arm: { down: boolean }
	): Promise<void> {
		arm.down = false;
		retry(s);
		await world.mine(s.w, 1);
		await alicePaid(s, invoice);
		const carol = s.w.hosts.carol;
		expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
		for (const part of parts) {
			expect(
				endsOf(sent, s.w.outChannel, part.id),
				`${keyOf(s.w.outChannel, part.id)} is fulfilled once and never failed`
			).to.deep.equal([UPDATE_FULFILL_HTLC]);
		}
		expect(unitsOf(carol, s.w.outChannel)).to.equal(6000n);
		expect(carolsRecord(s, invoice)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(
			s.received.filter((payment) =>
				payment.paymentHash.equals(invoice.paymentHash)
			).length,
			'payment:received once'
		).to.equal(1);
	}

	describe('the commit', () => {
		it("a records write that fails: the set is not settled ('write'), every part fails back, and Alice learns no preimage", async () => {
			const tag = 'parts-edge-write';
			const s = await openPartsScene(world, tag);
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			const invoice = await firstHeld(s, tag);
			// The first write that would make the record COMPLETED is refused.
			const holder = carol.node as unknown as {
				recovery: {
					commit: (transition: SafetyTransition) => IRecoveryCommitResult;
				};
			};
			const commit = holder.recovery.commit.bind(holder.recovery);
			let refused = 0;
			holder.recovery.commit = (transition): IRecoveryCommitResult => {
				const completes = transition.mutations.some(
					(mutation: RecoveryMutation) =>
						mutation.type === 'payment_state' &&
						mutation.paymentHash === hex(invoice.paymentHash) &&
						mutation.payment.status === PaymentStatus.COMPLETED
				);
				if (completes && refused === 0) {
					refused++;
					return {
						committed: false,
						released: [],
						frameSequence: null,
						error: new Error('the disk refuses the write')
					};
				}
				return commit(transition);
			};
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'the second part completes the set',
				() => notSettledOf(s, invoice).length > 0
			);
			await aliceFailed(s, invoice);
			await turns(100);
			expect(refused, 'the records write was tried once').to.equal(1);
			expectNothingSettled(s, invoice, 'write', watch, sent);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
		});

		it('a provider that refuses the fulfils after the commit: each part keeps its decision, its fulfil owed, and is fulfilled once the provider takes it', async () => {
			const tag = 'parts-edge-refused';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } }
			});
			const sent = wireWatch(s.w.hosts.carol);
			onCommit(s, () => {
				arm.down = true;
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			const parts = await committedUnfulfilled(s, invoice);
			expect(sent, 'nothing ended yet').to.deep.equal([]);
			await fulfilledOnce(s, invoice, parts, sent, arm);
		});

		it('the MPP timer never touches a committed set: past mppTimeoutMs with every fulfil owed, no part is failed, and each is fulfilled once the provider takes it', async () => {
			const tag = 'parts-edge-timer';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } }
			});
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			onCommit(s, () => {
				arm.down = true;
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			const parts = await committedUnfulfilled(s, invoice);
			const timer = timerOf(s);
			timer.mppTimeoutMs = 0;
			await turns(2);
			timer.failTimedOutMppPayments();
			await turns(50);
			expect(watch.fails, 'no part is failed').to.deep.equal([]);
			expect(
				receivedEntries(carol, s.w.outChannel, invoice.paymentHash).length
			).to.equal(2);
			await fulfilledOnce(s, invoice, parts, sent, arm);
			expect(watch.fails).to.deep.equal([]);
		});

		it('a committed part dispatched again, twice, is fulfilled once and never failed', async () => {
			const tag = 'parts-edge-dispatched';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } }
			});
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			onCommit(s, () => {
				arm.down = true;
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			const parts = await committedUnfulfilled(s, invoice);
			const node = carol.node as unknown as {
				handleIncomingHtlc: (
					channelId: Buffer,
					htlcId: bigint,
					amountMsat: bigint,
					paymentHash: Buffer
				) => void;
			};
			for (let round = 0; round < 2; round++) {
				for (const part of parts) {
					node.handleIncomingHtlc(
						s.w.outChannel,
						part.id,
						part.amountMsat,
						invoice.paymentHash
					);
				}
				await turns(50);
			}
			expect(watch.fails, 'no part is failed').to.deep.equal([]);
			expect(
				receivedEntries(carol, s.w.outChannel, invoice.paymentHash).length
			).to.equal(2);
			await fulfilledOnce(s, invoice, parts, sent, arm);
			expect(watch.fails).to.deep.equal([]);
		});

		it('the opt-in turned off after the commit changes nothing for the set: it is driven to its end the same way', async () => {
			const tag = 'parts-edge-opt-out';
			const arm = { down: false };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } }
			});
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			onCommit(s, () => {
				arm.down = true;
				// The configuration object the node reads at use.
				(
					carol.node as unknown as {
						auxiliaryChannels: { receiveInParts?: boolean };
					}
				).auxiliaryChannels.receiveInParts = false;
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			const parts = await committedUnfulfilled(s, invoice);
			expect(
				(
					carol.node as unknown as {
						auxiliaryChannels: { receiveInParts?: boolean };
					}
				).auxiliaryChannels.receiveInParts
			).to.equal(false);
			await fulfilledOnce(s, invoice, parts, sent, arm);
			expect(watch.fails).to.deep.equal([]);
		});
	});

	describe('no commit with a part at risk', () => {
		it("a part whose channel is on the chain at completion: the whole set fails back ('channel'), nothing written and nothing revealed, and the part on the chain is never claimed", async () => {
			const tag = 'parts-edge-risk-chain';
			const s = await openPartsScene(world, tag, {
				world: { secondOut: 'asset' },
				coins: 4
			});
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			const invoice = await firstHeld(s, tag);
			const [first] = receivedEntries(
				carol,
				s.w.outChannel,
				invoice.paymentHash
			);
			// The first part's channel goes to the chain.
			const closed = s.w.hosts.bob.node.forceCloseChannel(
				s.w.outChannel,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await world.mine(s.w, 1);
			sendPart(s.w, invoice, 2_000_000n, {
				next: aliasOf(s.w.hosts.bob, s.w.outChannel2!)
			});
			await rounds(
				'the second part completes the set',
				() => notSettledOf(s, invoice).length > 0
			);
			await turns(100);
			expectNothingSettled(s, invoice, 'channel', watch, sent);
			expect(heldOn(carol, s.w.outChannel2!, invoice.paymentHash)).to.equal(0);
			expect(unitsOf(carol, s.w.outChannel2!)).to.equal(1000n);
			// The part on the chain is left to Bob's timeout.
			await world.passTo(s.w, first.cltvExpiry - 1);
			for (
				let i = 0;
				i < 12 &&
				!receivedOutputs(carol, s.w.outChannel, invoice.paymentHash).some(
					isSpent
				);
				i++
			) {
				await world.mine(s.w, 1);
			}
			expect(
				receivedOutputs(carol, s.w.outChannel, invoice.paymentHash).some(
					isSpent
				),
				"Bob's timeout took the part back"
			).to.equal(true);
			expect(
				claimedByPreimage(s, s.w.outChannel, invoice.paymentHash)
			).to.deep.equal([]);
			for (
				let i = 0;
				i < 12 && alicesStatus(s, invoice) !== PaymentStatus.FAILED;
				i++
			) {
				await world.mine(s.w, 1);
			}
			expect(alicesStatus(s, invoice)).to.equal(PaymentStatus.FAILED);
		});

		it("a part with a fail owed at completion: the whole set fails back ('decided'), nothing written and nothing revealed", async () => {
			const tag = 'parts-edge-risk-owed';
			const keep = { keep: new Set<string>() };
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: keeping(keep) } }
			});
			const carol = s.w.hosts.carol;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			const invoice = await firstHeld(s, tag);
			const [first] = receivedEntries(
				carol,
				s.w.outChannel,
				invoice.paymentHash
			);
			// A fail of the first part that the provider refuses, so it is owed.
			keep.keep.add(keyOf(s.w.outChannel, first.id));
			const manager = carol.node.getChannelManager();
			const failed = manager.failHtlc(
				s.w.outChannel,
				first.id,
				Buffer.alloc(FAILURE_MESSAGE_LENGTH)
			);
			expect(failed.ok, 'the provider refuses the fail').to.equal(false);
			expect(manager.owesAuxiliaryRemoval(s.w.outChannel, first.id)).to.equal(
				true
			);
			watch.fails.splice(0);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'the second part completes the set',
				() => notSettledOf(s, invoice).length > 0
			);
			await turns(50);
			expectNothingSettled(s, invoice, 'decided', watch, sent);
			// The provider takes the fail again.
			keep.keep.clear();
			retry(s);
			await world.mine(s.w, 1);
			await aliceFailed(s, invoice);
			await turns(100);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
			expect(
				sent.filter((entry) => entry.startsWith(`${UPDATE_FULFILL_HTLC}:`))
			).to.deep.equal([]);
		});

		it("short fee coins on a node that forwards with requireFeeCoinsToSettle: the whole set fails back ('fee-coins'), nothing written and nothing revealed", async () => {
			const tag = 'parts-edge-risk-coins';
			// Of the fixed mode, Carol a node that forwards whose wallet has no coin.
			const s = await openPartsScene(world, tag, {
				world: { realInit: true },
				bob: { allowLegacyHtlcSignatures: undefined },
				carol: {
					allowLegacyHtlcSignatures: undefined,
					prepareForward: () => undefined,
					requireFeeCoinsToSettle: true
				},
				coins: 4,
				carolCoins: 0,
				blocks: 3
			});
			const carol = s.w.hosts.carol;
			expect(
				isFixedAssetHtlcChannel(
					carol.node
						.getChannelManager()
						.getChannel(s.w.outChannel)!
						.getFullState().channelType
				),
				'the channel is of the fixed mode'
			).to.equal(true);
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			const invoice = await firstHeld(s, tag);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'the second part completes the set',
				() => notSettledOf(s, invoice).length > 0
			);
			await aliceFailed(s, invoice);
			await turns(100);
			expectNothingSettled(s, invoice, 'fee-coins', watch, sent);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
		});

		it("a circular payment's set, whose record is the payer's own (OUTGOING): the whole set fails back ('record'), nothing written and nothing revealed", async () => {
			const tag = 'parts-edge-risk-circular';
			const s = await openPartsScene(world, tag, {
				world: { secondOut: 'ordinary' }
			});
			const { bob, carol } = s.w.hosts;
			const watch = watchManager(carol);
			const sent = wireWatch(carol);
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			// Carol pays a part of her own invoice: to Bob over their ordinary
			// channel, and back to her over the asset one, which makes her
			// record of the hash OUTGOING. A node sends no second part to its
			// own invoice, since it holds the preimage (assertHashUnpaid), so
			// Alice sends the part that completes the set.
			const circular = (partMsat: bigint): void => {
				carol.node.sendPaymentToRoute(
					{
						hops: [
							{
								pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
								shortChannelId: Buffer.alloc(8, 9),
								amountToForwardMsat: partMsat + partMsat / 50n + 1000n,
								outgoingCltvValue: 100
							},
							{
								pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
								shortChannelId: aliasOf(bob, s.w.outChannel),
								amountToForwardMsat: partMsat,
								outgoingCltvValue: 60
							}
						]
					},
					invoice.paymentHash,
					40,
					invoice.paymentSecret,
					invoice.totalMsat
				);
			};
			circular(3_000_000n);
			await rounds(
				'Carol is asked about the first part',
				() => asksFor(s, invoice).length === 1
			);
			expect(carolsRecord(s, invoice)?.direction).to.equal(
				PaymentDirection.OUTGOING
			);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(carol, invoice.paymentHash) === 1
			);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'the second part completes the set',
				() => notSettledOf(s, invoice).length > 0
			);
			await rounds(
				"Carol's own payment fails",
				() => carolsRecord(s, invoice)?.status === PaymentStatus.FAILED,
				60
			);
			expect([
				...new Set(notSettledOf(s, invoice).map((log) => log.data.reason))
			]).to.deep.equal(['record']);
			expect(
				watch.decisions.filter((decision) => decision.outcome === 'settle')
			).to.deep.equal([]);
			expect(watch.fulfils).to.deep.equal([]);
			expect(
				sent.filter((entry) =>
					entry.startsWith(`${UPDATE_FULFILL_HTLC}:${hex(s.w.outChannel)}`)
				)
			).to.deep.equal([]);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
		});
	});

	describe('a restart', () => {
		it("after the commit, with a part whose decision did not land and whose fulfil is refused: Carol's restore writes the decision before any block, and the part is fulfilled once the provider takes it", async () => {
			const tag = 'parts-edge-restart-decision';
			const keep = { keep: new Set<string>() };
			const s = await openPartsScene(world, tag, {
				world: { carolOnFile: true, wrapProvider: { carol: keeping(keep) } }
			});
			const carol = s.w.hosts.carol;
			// On this run of Carol's, the write of one part's decision fails.
			const write = { part: '' };
			const manager = carol.node.getChannelManager();
			const decide = manager.recordAuxiliaryHtlcDecision.bind(manager);
			manager.recordAuxiliaryHtlcDecision = (
				channelId,
				htlcId,
				outcome,
				preimage
			): boolean =>
				keyOf(channelId, htlcId) === write.part
					? false
					: decide(channelId, htlcId, outcome, preimage);
			onCommit(s, () => {
				const parts = openReceived(carol, s.w.outChannel);
				write.part = keyOf(s.w.outChannel, parts[parts.length - 1].id);
				keep.keep.add(write.part);
			});
			const invoice = await payInParts(s.w, tag, [3_000_000n, 2_000_000n]);
			await committed(s, invoice);
			await turns(50);
			const left = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
			expect(left.map((part) => keyOf(s.w.outChannel, part.id))).to.deep.equal([
				write.part
			]);
			const [part] = left;
			expect(decisionOf(carol, s.w.outChannel, part.id)).to.equal(undefined);

			// The provider still refuses the part's removal after the restart.
			const height = s.w.chain.height;
			await world.restartCarol(s.w, tag, { reconnect: false });
			listenCarol(s);
			expect(s.w.chain.height, 'no block since').to.equal(height);
			expect(
				decisionOf(s.w.hosts.carol, s.w.outChannel, part.id),
				'the decision is written at the restore'
			).to.equal('settle');
			await world.reconnect(s.w, 'out');
			expect(
				heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash),
				'its fulfil is refused on the reestablish'
			).to.equal(1);
			expect(decisionOf(s.w.hosts.carol, s.w.outChannel, part.id)).to.equal(
				'settle'
			);

			keep.keep.clear();
			retry(s);
			await world.mine(s.w, 1);
			await rounds(
				'the part is fulfilled',
				() =>
					heldOn(s.w.hosts.carol, s.w.outChannel, invoice.paymentHash) === 0,
				60
			);
			expect(unitsOf(s.w.hosts.carol, s.w.outChannel)).to.equal(6000n);
			expect(carolsRecord(s, invoice)!.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(
				s.received.filter((payment) =>
					payment.paymentHash.equals(invoice.paymentHash)
				).length,
				'payment:received once'
			).to.equal(1);
		});
	});

	describe('the row bound', () => {
		it("with a guardian room that holds one more part as an ordinary set's row sizes it but not with each asset part's value at its widest, a part is refused (settled_row_full) and the parts taken stay held, unsettled", async () => {
			const tag = 'parts-edge-row';
			const s = await openPartsScene(world, tag);
			const carol = s.w.hosts.carol;
			const node = carol.node as unknown as {
				payments: Map<string, unknown>;
				settledPaymentMutation: (payment: unknown) => RecoveryMutation;
				recoveryJournal: unknown;
			};
			const invoice = partsInvoice(s.w, tag, 5_000_000n);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'Carol holds the first part in the set',
				() => collected(carol, invoice.paymentHash) === 1
			);
			// The row the set is sized at with the first part and one more, as
			// a part's arrival measures it.
			const sized = encodedMutationBytes(
				node.settledPaymentMutation(node.payments.get(hex(invoice.paymentHash)))
			);
			// One more settledHtlcs entry is about 69 bytes, and one more entry
			// of _auxiliaryReceivedParts, at a full u64, about 96: the room
			// holds another part as an ordinary set sizes it, not as an asset
			// set does.
			const entry = JSON.stringify(`${hex(s.w.outChannel)}:1`).length + 1;
			const room = sized + entry + 20;
			node.recoveryJournal = {
				mutationRoom: (): number => room,
				getDurability: (): string => 'local',
				needsSnapshotSchemaRepair: (): boolean => false,
				snapshotSchemaRepair: (): null => null,
				prepareForReplication: (): void => undefined
			};
			const refusals: Log[] = [];
			carol.node.on('log', (log: Log) => {
				if (
					log.action === 'settled_row_full' &&
					log.data.paymentHash === hex(invoice.paymentHash)
				) {
					refusals.push(log);
				}
			});
			sendPart(s.w, invoice, 2_000_000n);
			await turns(200);
			sendPart(s.w, invoice, 1_000_000n);
			await rounds('a part is refused for the room', () => refusals.length > 0);
			await turns(200);
			expect(
				carolsRecord(s, invoice)!.status,
				'the set is not settled'
			).to.equal(PaymentStatus.PENDING);
			expect(
				s.w.hosts.alice.node.getPayment(invoice.paymentHash)?.preimage
			).to.equal(undefined);
			const held = collected(carol, invoice.paymentHash);
			expect(held, 'the parts taken stay held').to.be.within(1, 2);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(held);
		});
	});

	describe('a set that never completes', () => {
		it('each part fails back at the timeout, its fail owed while the provider refuses it and gone once it takes it; the host is told of each HTLC', async () => {
			const tag = 'parts-edge-timeout';
			const arm = { down: false };
			const told: Array<{ key: string; outcome: string }> = [];
			const s = await openPartsScene(world, tag, {
				world: { wrapProvider: { carol: refusing(arm) } },
				carol: {
					onHtlcResolved: (context): void => {
						told.push({
							key: `${hex(context.channelId)}:${context.htlcId}:${hex(
								context.paymentHash
							)}`,
							outcome: context.outcome
						});
					}
				}
			});
			const carol = s.w.hosts.carol;
			const sent = wireWatch(carol);
			// Two parts of a set that needs 6,000,000.
			const invoice = partsInvoice(s.w, tag, 6_000_000n);
			sendPart(s.w, invoice, 3_000_000n);
			sendPart(s.w, invoice, 2_000_000n);
			await rounds(
				'Carol holds both parts in the set',
				() => collected(carol, invoice.paymentHash) === 2,
				40
			);
			const parts = receivedEntries(carol, s.w.outChannel, invoice.paymentHash);
			expect(parts.length).to.equal(2);
			const told_ = (): typeof told =>
				told.filter((end) => end.key.endsWith(hex(invoice.paymentHash)));
			expect(told_()).to.deep.equal([]);

			arm.down = true;
			const timer = timerOf(s);
			timer.mppTimeoutMs = 0;
			await turns(2);
			timer.failTimedOutMppPayments();
			await turns(50);
			const manager = carol.node.getChannelManager();
			for (const part of parts) {
				expect(
					manager.owesAuxiliaryRemoval(s.w.outChannel, part.id),
					'the fail is owed'
				).to.equal(true);
			}
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(2);
			expect(told_(), 'nothing ended yet').to.deep.equal([]);

			arm.down = false;
			retry(s);
			await world.mine(s.w, 1);
			await aliceFailed(s, invoice);
			await turns(100);
			expect(heldOn(carol, s.w.outChannel, invoice.paymentHash)).to.equal(0);
			for (const part of parts) {
				expect(
					endsOf(sent, s.w.outChannel, part.id),
					'each part fails back once'
				).to.deep.equal([UPDATE_FAIL_HTLC]);
				expect(manager.owesAuxiliaryRemoval(s.w.outChannel, part.id)).to.equal(
					false
				);
			}
			expect(
				sent.filter((entry) =>
					entry.startsWith(`${UPDATE_FAIL_MALFORMED_HTLC}:`)
				)
			).to.deep.equal([]);
			expect(told_().map((end) => end.outcome)).to.deep.equal([
				'failed',
				'failed'
			]);
			expect(
				told_()
					.map((end) => end.key.split(':')[1])
					.sort()
			).to.deep.equal(parts.map((part) => part.id.toString()).sort());
			expect(unitsOf(carol, s.w.outChannel)).to.equal(1000n);
			expect(carolsRecord(s, invoice)!.status).to.not.equal(
				PaymentStatus.COMPLETED
			);
		});
	});
});
