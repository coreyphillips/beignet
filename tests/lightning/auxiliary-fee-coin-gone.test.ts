/**
 * Asset channels (issue #2093): a fee coin pledged to a spend is spent by
 * another transaction before the spend can go out.
 *
 * The spend that names the coin is refused by the network, so the wallet's
 * server never knows it. When the fee is next raised the pool sees that the
 * transaction it is asked to replace is unknown and that the wallet no
 * longer lists the coin: the coin leaves the action, another takes its
 * place, and the spend goes out and confirms.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { expect } from 'chai';
import { ecc } from '../../src/utils/ecc';
import { OutputStatus, OutputType } from '../../src/lightning/chain/types';
import type { ITrackedOutput } from '../../src/lightning/chain/types';
import { withAssetOpens, type IAssetHost } from './helpers/auxiliary-nodes';
import { hash } from './helpers/auxiliary-pair';
import {
	SWEEP_DESTINATION,
	assetChainWorld,
	holdUnits,
	settle,
	trackedOutputs,
	type IAssetChainPair
} from './helpers/auxiliary-on-chain';

describe('asset channels: a fee coin of a spend that went elsewhere', function () {
	this.timeout(180000);
	withAssetOpens();
	const world = assetChainWorld();
	afterEach(() => world.dispose());

	const htlcOf = (
		host: IAssetHost,
		pair: IAssetChainPair
	): ITrackedOutput | undefined =>
		trackedOutputs(host, pair.channelId).find(
			(output) =>
				output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC
		);
	const isSpent = (output: ITrackedOutput | undefined): boolean =>
		!!output &&
		[OutputStatus.SPEND_CONFIRMED, OutputStatus.IRREVOCABLY_RESOLVED].includes(
			output.status
		);

	it('lets go of the spent coin at the next raise, takes another, and takes its HTLC back', async () => {
		const tag = 'fee-coin-gone';
		const pair = await world.open(tag, {
			feeWallet: { alice: true, bob: true },
			hooks: {
				bob: {
					valueIncomingHtlc: (context: { auxiliaryAmount?: bigint }): bigint =>
						context.auxiliaryAmount! * 1000n
				}
			}
		});
		for (const wallet of [pair.wallets.alice!, pair.wallets.bob!]) {
			wallet.fund(100_000);
			wallet.fund(100_000);
		}
		await world.mine(pair, 1);
		const held = await holdUnits(pair, 5000n, 'coin gone');
		const closed = pair.alice.node.forceCloseChannel(
			pair.channelId,
			SWEEP_DESTINATION
		);
		expect(closed.ok, closed.error).to.equal(true);
		await settle();
		await world.mine(pair, 2);
		const whole = htlcOf(pair.alice, pair)!;
		const funded = bitcoin.Transaction.fromHex(whole.sweepTxHex!);
		expect(funded.ins.length).to.equal(2);

		// The fee coin goes elsewhere, by the wallet's own key.
		const secret = hash(`fee wallet ${tag} alice`);
		const pubkey = Buffer.from(ecc.pointFromScalar(secret, true)!);
		const coinTxid = Buffer.from(funded.ins[1].hash).reverse().toString('hex');
		const coinValue =
			pair.chain.transaction(coinTxid)!.outs[funded.ins[1].index].value;
		const elsewhere = new bitcoin.Transaction();
		elsewhere.version = 2;
		elsewhere.addInput(
			Buffer.from(funded.ins[1].hash),
			funded.ins[1].index,
			0xfffffffd
		);
		elsewhere.addOutput(SWEEP_DESTINATION, coinValue - 300);
		const digest = elsewhere.hashForWitnessV0(
			0,
			bitcoin.payments.p2pkh({ pubkey }).output!,
			coinValue,
			bitcoin.Transaction.SIGHASH_ALL
		);
		elsewhere.setWitness(0, [
			bitcoin.script.signature.encode(
				Buffer.from(ecc.sign(digest, secret)),
				bitcoin.Transaction.SIGHASH_ALL
			),
			pubkey
		]);
		pair.chain.mine(elsewhere);
		await settle();
		expect(pair.chain.confirmed.has(elsewhere.getId())).to.equal(true);

		// To the expiry and past it, block by block.
		pair.chain.advance(held.cltvExpiry - 1 - pair.chain.height);
		await settle();
		for (let i = 0; i < 12 && !isSpent(htlcOf(pair.alice, pair)); i++) {
			await world.mine(pair, 1);
		}
		const after = htlcOf(pair.alice, pair)!;
		expect(isSpent(after), 'taken back').to.equal(true);
		const taken = pair.chain.confirmed.get(after.resolutionTxid!)!;
		expect(taken.height).to.be.at.most(held.cltvExpiry + 8);
		// The raise asks a higher rate, so it may take two coins: none of
		// them is the coin that went elsewhere.
		expect(taken.tx.ins.length).to.be.within(2, 3);
		const spentCoin = `${coinTxid}:${funded.ins[1].index}`;
		expect(
			taken.tx.ins
				.slice(1)
				.map(
					(input) =>
						`${Buffer.from(input.hash).reverse().toString('hex')}:${
							input.index
						}`
				)
		).to.not.include(spentCoin);
		// The spend over the spent coin was refused from the block it first
		// went out in until the next raise, six blocks later, and is not
		// signed over that coin again.
		const overSpentCoin = (): number =>
			pair.backends.alice.refused.filter((each) =>
				each.reason.includes(spentCoin)
			).length;
		const refused = overSpentCoin();
		expect(refused).to.be.within(1, 10);
		await world.mine(pair, 3);
		expect(overSpentCoin()).to.equal(refused);
		// The action's record names the coin it let go of.
		const journal = JSON.parse(
			[...pair.wallets.alice!.journal.rows.values()][0]
		) as {
			actions: Record<string, { gone?: Array<{ outpoint: string }> }>;
			retiredIds?: string[];
		};
		const letGo = Object.values(journal.actions).flatMap(
			(action) => action.gone ?? []
		);
		expect(letGo.map((coin) => coin.outpoint)).to.deep.equal([spentCoin]);
	});
});
