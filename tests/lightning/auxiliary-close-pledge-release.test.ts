/**
 * Asset channels (issue #2093): a commitment that lost the funding output.
 *
 * A node that force closes an asset channel offers its commitment and a
 * child of it that a coin of its wallet pays for. When another transaction
 * is in a block as the spend of the funding output, neither can confirm
 * any more: both are no longer offered, and the coin the child took is free
 * again in the handling of that block. The node whose commitment did
 * confirm no longer lists a hold for the coin its own child spent.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import { connectHosts, withAssetOpens } from './helpers/auxiliary-nodes';
import type { IChainWallet } from './helpers/auxiliary-fee-wallet';
import {
	assetChainWorld,
	errorsOf,
	payUnits,
	settle,
	SWEEP_DESTINATION,
	trackedOutputs
} from './helpers/auxiliary-on-chain';

describe('asset channels: a commitment that lost the funding output', function () {
	this.timeout(240_000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());
	const valueIncomingHtlc = (context: { auxiliaryAmount?: bigint }): bigint =>
		(context.auxiliaryAmount ?? 0n) * 1000n;
	const PLEDGE = 'funding-pledge';
	const POOL = 'fixed-output-fees:';
	const done = [
		OutputStatus.SPEND_CONFIRMED,
		OutputStatus.IRREVOCABLY_RESOLVED
	];
	const key = (coin: { tx_hash: string; tx_pos: number }): string =>
		`${coin.tx_hash}:${coin.tx_pos}`;
	/** What a wallet holds, and how much of it each kind of hold keeps back. */
	const read = (
		wallet: IChainWallet
	): { total: number; spendable: number; pool: number; pledged: string[] } => {
		const holds = new Map(
			(wallet.wallet.listFrozenUtxos?.() ?? []).map((hold) => [
				key(hold),
				hold.freezeTag ?? ''
			])
		);
		let total = 0;
		let spendable = 0;
		let pool = 0;
		for (const coin of wallet.coins()) {
			const tag = holds.get(key(coin));
			total += coin.value;
			if (tag === undefined) spendable += coin.value;
			else if (tag.startsWith(POOL)) pool += coin.value;
		}
		return {
			total,
			spendable,
			pool,
			pledged: [...holds].filter(([, tag]) => tag === PLEDGE).map(([at]) => at)
		};
	};

	it('frees the coin of the child and offers neither again once the other commitment is in a block', async () => {
		const tag = 'pledge-release';
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: { bob: { valueIncomingHtlc } }
		});
		const { channelId } = pair;
		const wallet = pair.wallets.alice!;
		wallet.fund(1_000_000);
		pair.wallets.bob!.fund(1_000_000);
		await world.mine(pair, 1);
		await payUnits(pair, 100n);
		const before = read(wallet);
		expect(before).to.deep.include({ spendable: 1_000_000, pledged: [] });

		// Alice is away, and Bob closes by himself.
		let theirs = '';
		await world.restartAlice(pair, tag, undefined, () => {
			const closed = pair.bob.node.forceCloseChannel(
				channelId,
				SWEEP_DESTINATION
			);
			if (!closed.ok) throw new Error(closed.error);
			theirs = closed.commitmentTxid!;
		});
		for (let i = 0; i < 5; i++) await settle();
		expect(pair.chain.mempool.has(theirs), 'in the mempool').to.equal(true);
		expect(pair.chain.confirmed.has(theirs), 'in no block').to.equal(false);

		// Everything Alice offers the network from here on.
		const offers: Array<{ txid: string; tx: bitcoin.Transaction }> = [];
		const backend = pair.backends.alice;
		const send = backend.broadcastTransaction.bind(backend);
		backend.broadcastTransaction = async (raw: string): Promise<string> => {
			const tx = bitcoin.Transaction.fromHex(raw);
			offers.push({ txid: tx.getId(), tx });
			return send(raw);
		};

		// Alice is back, hears from Bob that the channel is gone, and closes
		// with the commitment she has.
		connectHosts(pair.alice, pair.bob);
		for (const [host, peer] of [
			[pair.alice, pair.bob],
			[pair.bob, pair.alice]
		]) {
			host.node
				.getChannelManager()
				.handlePeerReconnected(peer.node.getNodeId());
		}
		for (let i = 0; i < 10; i++) await settle();
		const fundingId = pair.funding.getId();
		const own = offers.find(
			(offer) =>
				offer.txid !== theirs &&
				Buffer.from(offer.tx.ins[0].hash).reverse().toString('hex') ===
					fundingId
		);
		expect(
			own,
			`her commitment: ${errorsOf(pair.alice).join('; ')}`
		).to.not.equal(undefined);
		const child = offers.find(
			(offer) =>
				Buffer.from(offer.tx.ins[0].hash).reverse().toString('hex') ===
				own!.txid
		);
		expect(child, 'the child of her commitment').to.not.equal(undefined);
		const taken = child!.tx.ins
			.slice(1)
			.map(
				(input) =>
					`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`
			);
		expect(read(wallet).pledged, 'held for the child').to.deep.equal(taken);
		expect(read(wallet).spendable).to.equal(0);

		// Bob's commitment is in a block.
		await world.mine(pair, 1);
		for (let i = 0; i < 5; i++) await settle();
		expect(pair.chain.confirmed.has(theirs)).to.equal(true);
		expect(read(wallet).pledged, 'held for a void child').to.deep.equal([]);
		expect(
			read(pair.wallets.bob!).pledged,
			'held for a coin his child spent'
		).to.deep.equal([]);
		const offered = offers.length;

		// Blocks until Alice has swept what is hers on Bob's commitment.
		let swept = false;
		for (let i = 0; i < 40 && !swept; i++) {
			await world.mine(pair, 1);
			for (let j = 0; j < 5; j++) await settle();
			swept = trackedOutputs(pair.alice, channelId).some(
				(output) =>
					output.outputType === OutputType.TO_REMOTE &&
					done.includes(output.status)
			);
		}
		expect(swept, errorsOf(pair.alice).join('; ')).to.equal(true);
		expect(
			offers
				.slice(offered)
				.filter((offer) => [own!.txid, child!.txid].includes(offer.txid))
				.map((offer) => offer.txid),
			'offered again'
		).to.deep.equal([]);

		// Her bitcoin: what it was, less the fee coins and the fees.
		const after = read(wallet);
		expect(after.pledged).to.deep.equal([]);
		expect(after.spendable).to.equal(after.total - after.pool);
		expect(before.total - after.total).to.be.within(0, 20_000);
		expect(after.spendable).to.be.at.least(
			before.spendable - after.pool - 20_000
		);
	});
});
