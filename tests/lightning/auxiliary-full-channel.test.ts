/**
 * Asset channels (issue #2098, step 6): a channel full of asset HTLCs goes
 * to the chain, on a node that forwards. Twenty HTLCs each way by default
 * (ASSET_FULL_CHANNEL_HTLCS): Alice's twenty to Bob, which Bob settles, and
 * Bob's twenty to Alice, which she holds. Each case closes the channel one
 * way and checks that every spend with a deadline confirms before it, that
 * every other output is spent by the side it belongs to once it can be,
 * and that Bob's fee coins came from his preparation and not from a split
 * made inside a claim.
 *
 * Slow: a case runs for minutes. `npm run test:full-channel` runs them
 * (ASSET_FULL_CHANNEL=1); `test:local` skips them.
 */

import * as fs from 'fs';
import { expect } from 'chai';
import {
	FIXED_OUTPUT_DEADLINE_SPEND_VBYTES,
	FIXED_OUTPUT_FEE_INPUT_VBYTES
} from '../../src/lightning/channel/fixed-output-reserve';
import { isFixedAssetHtlcChannel } from '../../src/lightning/channel/types';
import {
	CommitmentType,
	OutputStatus,
	OutputType,
	type ITrackedOutput
} from '../../src/lightning/chain/types';
import type { IFixedOutputFeePolicy } from '../../src/lightning/wallet/fixed-output-fees';
import { withAssetOpens } from './helpers/auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	disconnect,
	errorsOf,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

const RUN = process.env.ASSET_FULL_CHANNEL === '1';
const N = Number(process.env.ASSET_FULL_CHANNEL_HTLCS ?? 20);

(RUN ? describe : describe.skip)(
	`a channel full of asset HTLCs, ${N} each way, on the chain (#2098 step 6)`,
	function () {
		this.timeout(3_600_000);
		withAssetOpens();
		const world = assetChainWorld();
		afterEach(() => world.dispose());
		const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
			(context.auxiliaryAmount ?? 0n) * 1000n;
		const prepareForward = (): undefined => undefined;
		/** The sizing of the contract for a channel of N each way, with room. */
		const policy: Partial<IFixedOutputFeePolicy> = {
			maxFeeSatoshis: 100_000n,
			maxTotalFeeSatoshis: 10_000_000n,
			maxPreparationFeeSatoshis: 20_000n,
			feeCoinCount: 16
		};

		interface IFull {
			pair: IAssetChainPair;
			/** Alice's HTLCs to Bob, which Bob settles. */
			toBob: Array<{
				paymentHash: Buffer;
				preimage: Buffer;
				cltvExpiry: number;
			}>;
			/** Bob's HTLCs to Alice, which she holds. */
			toAlice: Array<{ paymentHash: Buffer; cltvExpiry: number }>;
			/** Bob's splits of fee coins before the close. */
			splitsBefore: number;
		}

		const full = async (tag: string): Promise<IFull> => {
			const both = {
				valueIncomingHtlc,
				prepareForward,
				maxHtlcs: N,
				allowLegacyHtlcSignatures: undefined
			};
			const pair = await world.open(tag, {
				realInit: true,
				openerUnits: 1_000_000n,
				acceptorUnits: 1_000_000n,
				pushMsat: 600_000_000n,
				feeWallet: { alice: policy, bob: policy },
				hooks: { alice: both, bob: both }
			});
			expect(
				isFixedAssetHtlcChannel(
					pair.bob.node
						.getChannelManager()
						.getChannel(pair.channelId)!
						.getFullState().channelType
				),
				'the channel is of the fixed mode'
			).to.equal(true);
			for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
				for (let i = 0; i < 8; i++) wallet.fund(1_000_000);
			}
			// Both prepare their fee coins before the channel fills.
			await world.mine(pair, 6);
			const swapped = { ...pair, alice: pair.bob, bob: pair.alice };
			const toAlice = [];
			for (let i = 0; i < N; i++) {
				toAlice.push(
					await holdUnits(swapped, 1000n, `${tag} to alice ${i}`, 20)
				);
			}
			const toBob = [];
			for (let i = 0; i < N; i++) {
				toBob.push(await holdUnits(pair, 1000n, `${tag} to bob ${i}`, 40));
			}
			const state = pair.bob.node
				.getChannelManager()
				.getChannel(pair.channelId)!
				.getFullState();
			expect(state.htlcs.size, 'the channel is full').to.equal(2 * N);
			const status = pair.bob.node.getFixedOutputFeeStatus();
			const splitsBefore =
				status?.available === true ? status.splits.length : 0;
			return { pair, toBob, toAlice, splitsBefore };
		};

		/**
		 * Bob decides to settle Alice's HTLCs while she cannot be reached: each
		 * is a claim with a deadline once the channel is on the chain.
		 */
		const settleAway = async (f: IFull): Promise<void> => {
			disconnect(f.pair);
			for (const held of f.toBob) {
				f.pair.bob.node.settleHeldHtlc(held.paymentHash, held.preimage);
			}
			await settle();
		};

		const outputsOf = (
			f: IFull,
			type: OutputType,
			hashes: Buffer[]
		): ITrackedOutput[] =>
			trackedOutputs(f.pair.bob, f.pair.channelId).filter(
				(output) =>
					output.outputType === type &&
					!output.isSecondLevelHtlc &&
					hashes.some((hash) => output.paymentHash?.equals(hash))
			);
		const spentAt = (output: ITrackedOutput): number | undefined =>
			output.status === OutputStatus.SPEND_CONFIRMED ||
			output.status === OutputStatus.IRREVOCABLY_RESOLVED
				? output.confirmationHeight
				: undefined;
		const mineUntil = async (
			f: IFull,
			what: string,
			reached: () => boolean,
			most: number
		): Promise<void> => {
			for (let i = 0; i < most && !reached(); i++) await world.mine(f.pair, 1);
			if (!reached()) {
				throw new Error(
					`never reached: ${what} at ${
						f.pair.chain.height
					}; bob outputs [${trackedOutputs(f.pair.bob, f.pair.channelId)
						.map(
							(o) =>
								`${o.outputType}${o.isSecondLevelHtlc ? '/2nd' : ''}:${
									o.status
								}@${o.confirmationHeight}${
									o.cltvExpiry ? ` cltv ${o.cltvExpiry}` : ''
								}${
									o.auxiliaryFeeWait ? ` (wait ${o.auxiliaryFeeWait.code})` : ''
								}`
						)
						.join(', ')}]; bob: ${errorsOf(f.pair.bob).slice(-6).join(' | ')}`
				);
			}
		};

		/**
		 * Let empty blocks pass up to `before` blocks ahead of the earliest
		 * expiry of Bob's HTLCs to Alice: nothing is due in between, and the
		 * nodes see only the last of them.
		 */
		const passToTimeouts = async (f: IFull, before: number): Promise<void> => {
			const earliest = Math.min(...f.toAlice.map((held) => held.cltvExpiry));
			const blocks = earliest - before - f.pair.chain.height;
			if (blocks > 1) {
				f.pair.chain.advance(blocks);
				await settle();
			}
		};

		/** Each claim with a deadline confirmed before it, by Bob's own spend. */
		const expectClaimsInTime = (f: IFull): void => {
			const claims = outputsOf(
				f,
				OutputType.RECEIVED_HTLC,
				f.toBob.map((held) => held.paymentHash)
			);
			expect(claims, 'every settled HTLC is on the chain').to.have.length(N);
			for (const claim of claims) {
				const at = spentAt(claim);
				expect(
					at,
					`the claim of ${claim.txid}:${claim.outputIndex}`
				).to.not.equal(undefined);
				expect(at! < claim.cltvExpiry!, 'before its deadline').to.equal(true);
			}
		};

		/** Bob's fee coins came from his preparation, not a claim's own split. */
		const expectPreparedAhead = (f: IFull): void => {
			const status = f.pair.bob.node.getFixedOutputFeeStatus();
			if (status?.available !== true) throw new Error('Bob has no pool');
			expect(status.lastRefusal?.code).to.not.equal('FEE_ACTION_CAP_EXHAUSTED');
			expect(status.lastRefusal?.code).to.not.equal('FEE_BUDGET_EXHAUSTED');
			expect(
				errorsOf(f.pair.bob).filter((e) => e.includes('peer can now take'))
			).to.deep.equal([]);
		};

		/**
		 * Every spend Bob confirmed of these outputs is, without its fee inputs
		 * (each a P2WPKH input), no larger than the spend a kept coin is sized
		 * for.
		 */
		const expectSizesWithinReserve = (
			f: IFull,
			outputs: ITrackedOutput[]
		): void => {
			for (const output of outputs) {
				const spend = f.pair.chain.confirmed.get(output.resolutionTxid ?? '');
				if (!spend) continue;
				const own =
					spend.tx.virtualSize() -
					FIXED_OUTPUT_FEE_INPUT_VBYTES * (spend.tx.ins.length - 1);
				expect(
					own,
					`the spend of ${output.outputType} ${output.txid}:${output.outputIndex}`
				).to.be.at.most(FIXED_OUTPUT_DEADLINE_SPEND_VBYTES);
			}
		};

		it("Bob's commitment: every claim confirms before its deadline, every timeout after its expiry, and the fee coins were prepared ahead", async () => {
			const f = await full('full-own');
			await settleAway(f);
			const closed = f.pair.bob.node.forceCloseChannel(
				f.pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(f.pair, 1);
			expect(
				f.pair.bob.node.getChannelMonitorState(f.pair.channelId)!
					.commitmentBroadcast
			).to.include({ commitmentType: CommitmentType.OUR_COMMITMENT });
			const claimed = (): boolean =>
				outputsOf(
					f,
					OutputType.RECEIVED_HTLC,
					f.toBob.map((held) => held.paymentHash)
				).every((output) => spentAt(output) !== undefined);
			await mineUntil(f, 'every claim in a block', claimed, 40);
			expectClaimsInTime(f);
			const timedOut = (): boolean =>
				outputsOf(
					f,
					OutputType.OFFERED_HTLC,
					f.toAlice.map((held) => held.paymentHash)
				).every((output) => spentAt(output) !== undefined);
			await passToTimeouts(f, 10);
			await mineUntil(f, 'every timeout in a block', timedOut, 40);
			for (const output of outputsOf(
				f,
				OutputType.OFFERED_HTLC,
				f.toAlice.map((held) => held.paymentHash)
			)) {
				expect(
					spentAt(output)! >= output.cltvExpiry!,
					'after its expiry'
				).to.equal(true);
			}
			expectSizesWithinReserve(f, [
				...outputsOf(
					f,
					OutputType.RECEIVED_HTLC,
					f.toBob.map((held) => held.paymentHash)
				),
				...outputsOf(
					f,
					OutputType.OFFERED_HTLC,
					f.toAlice.map((held) => held.paymentHash)
				)
			]);
			expectPreparedAhead(f);
		});

		it("Alice's commitment: Bob claims every HTLC Alice offered before its deadline, and times his own out after their expiry", async () => {
			const f = await full('full-peer');
			await settleAway(f);
			const closed = f.pair.alice.node.forceCloseChannel(
				f.pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(f.pair, 1);
			expect(
				f.pair.bob.node.getChannelMonitorState(f.pair.channelId)!
					.commitmentBroadcast
			).to.include({ commitmentType: CommitmentType.THEIR_CURRENT_COMMITMENT });
			const claimed = (): boolean =>
				outputsOf(
					f,
					OutputType.RECEIVED_HTLC,
					f.toBob.map((held) => held.paymentHash)
				).every((output) => spentAt(output) !== undefined);
			await mineUntil(f, 'every claim in a block', claimed, 40);
			expectClaimsInTime(f);
			const timedOut = (): boolean =>
				outputsOf(
					f,
					OutputType.OFFERED_HTLC,
					f.toAlice.map((held) => held.paymentHash)
				).every((output) => spentAt(output) !== undefined);
			await passToTimeouts(f, 10);
			await mineUntil(f, 'every timeout in a block', timedOut, 40);
			expectSizesWithinReserve(f, [
				...outputsOf(
					f,
					OutputType.RECEIVED_HTLC,
					f.toBob.map((held) => held.paymentHash)
				),
				...outputsOf(
					f,
					OutputType.OFFERED_HTLC,
					f.toAlice.map((held) => held.paymentHash)
				)
			]);
			expectPreparedAhead(f);
		});

		it("a revoked commitment of Alice's with every HTLC on it: Bob punishes every output, the HTLCs' all within a few blocks", async () => {
			const f = await full('full-revoked');
			const { pair } = f;
			const copy = `${pair.alicePath}.kept`;
			(
				pair.alice.storage as unknown as {
					db: { exec(sql: string): void };
				}
			).db.exec(`VACUUM INTO '${copy}'`);
			// Every HTLC is failed back, so the full commitment is revoked.
			for (const held of f.toBob)
				pair.bob.node.cancelHoldInvoice(held.paymentHash);
			for (const held of f.toAlice) {
				pair.alice.node.cancelHoldInvoice(held.paymentHash);
			}
			const htlcs = (): number =>
				pair.alice.node
					.getChannelManager()
					.getChannel(pair.channelId)!
					.getFullState().htlcs.size;
			for (let i = 0; i < 400 && htlcs() > 0; i++) await settle();
			expect(htlcs(), 'every HTLC failed back').to.equal(0);
			await world.restartAlice(pair, 'full-revoked', undefined, () => {
				for (const suffix of ['', '-wal', '-shm']) {
					fs.rmSync(`${pair.alicePath}${suffix}`, { force: true });
				}
				fs.copyFileSync(copy, pair.alicePath);
			});
			const closed = pair.alice.node.forceCloseChannel(
				pair.channelId,
				SWEEP_DESTINATION
			);
			expect(closed.ok, closed.error).to.equal(true);
			await settle();
			await world.mine(pair, 1);
			const confirmedAt = pair.chain.height;
			expect(
				pair.bob.node.getChannelMonitorState(pair.channelId)!
					.commitmentBroadcast
			).to.include({
				txid: closed.commitmentTxid,
				commitmentType: CommitmentType.THEIR_REVOKED_COMMITMENT
			});
			const htlcOutputs = (): ITrackedOutput[] =>
				trackedOutputs(pair.bob, pair.channelId).filter(
					(output) =>
						output.txid === closed.commitmentTxid &&
						(output.outputType === OutputType.OFFERED_HTLC ||
							output.outputType === OutputType.RECEIVED_HTLC)
				);
			expect(
				htlcOutputs(),
				'every HTLC is on the revoked commitment'
			).to.have.length(2 * N);
			await mineUntil(
				f,
				'every penalty in a block',
				() => htlcOutputs().every((output) => spentAt(output) !== undefined),
				20
			);
			for (const output of htlcOutputs()) {
				expect(
					spentAt(output)! - confirmedAt,
					'blocks to its penalty'
				).to.be.at.most(10);
			}
			expectSizesWithinReserve(f, htlcOutputs());
			fs.rmSync(copy, { force: true });
			expectPreparedAhead(f);
		});
	}
);
