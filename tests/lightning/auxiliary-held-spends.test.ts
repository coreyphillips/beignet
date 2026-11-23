/**
 * Asset channels (issue #2098, step 6): the spends of an asset channel's
 * units that wait for the channel's monitor row to be stored are kept one
 * for each output they spend, so a channel full of HTLCs on the chain loses
 * none of them however many there are.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import {
	ChannelManager,
	type IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import type { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { COMMIT_ALL } from './helpers/channel-persistence';

const seedFor = (id: string): Buffer =>
	crypto
		.createHash('sha256')
		.update(Buffer.from(`auxiliary-held-spends-${id}`))
		.digest();

const privAt = (seed: Buffer, i: number): Buffer =>
	crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([i]))
		.digest();

const basepointsOf = (seed: Buffer): IChannelBasepoints => ({
	fundingPubkey: getPublicKey(privAt(seed, 0)),
	revocationBasepoint: getPublicKey(privAt(seed, 1)),
	paymentBasepoint: getPublicKey(privAt(seed, 2)),
	delayedPaymentBasepoint: getPublicKey(privAt(seed, 3)),
	htlcBasepoint: getPublicKey(privAt(seed, 4)),
	firstPerCommitmentPoint: Buffer.alloc(33)
});

/** The output a spend of the tests spends: one of a commitment's. */
const COMMITMENT = crypto.createHash('sha256').update('commitment').digest();

/**
 * A spend of output `index` of the commitment, with a fee input that says
 * which form of the spend it is.
 */
const spendOf = (index: number, form: number): Buffer => {
	const tx = new bitcoin.Transaction();
	tx.addInput(Buffer.from(COMMITMENT), index);
	tx.addInput(Buffer.alloc(32, form), 1);
	tx.addOutput(
		Buffer.concat([Buffer.from('5120', 'hex'), Buffer.alloc(32, 9)]),
		354
	);
	return tx.toBuffer();
};

/** Which output of the commitment a spend spends. */
const outputOf = (tx: Buffer): number =>
	bitcoin.Transaction.fromBuffer(tx).ins[0].index;

describe('asset channels: spends of units held for the monitor row, one for each output (#2098 step 6)', () => {
	let persisted = false;
	const sent: Buffer[] = [];
	const said: string[] = [];
	let manager: ChannelManager;
	const channelId = Buffer.alloc(32, 7);
	const hold = (tx: Buffer): void =>
		(
			manager as unknown as {
				broadcastAuxiliarySpend(id: Buffer, raw: Buffer): void;
			}
		).broadcastAuxiliarySpend(channelId, tx);
	const release = (): void =>
		(
			manager as unknown as { releaseHeldAuxiliarySpends(hex: string): void }
		).releaseHeldAuxiliarySpends(channelId.toString('hex'));

	beforeEach(() => {
		persisted = false;
		sent.length = 0;
		said.length = 0;
		const seed = seedFor('node');
		const config: IChannelManagerConfig = {
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: basepointsOf(seed),
			localPerCommitmentSeed: seedFor('commit'),
			localFundingPrivkey: privAt(seed, 0),
			htlcBasepointSecret: privAt(seed, 4),
			persistence: COMMIT_ALL,
			isMonitorPersisted: () => persisted
		};
		manager = new ChannelManager(config);
		manager.on('broadcast:tx', (tx: Buffer) => sent.push(Buffer.from(tx)));
		manager.on('error', (_id: unknown, message: unknown) =>
			said.push(String(message))
		);
	});

	it('keeps the spend of each of 40 outputs while the row cannot be stored, and sends every one of them once it is', () => {
		for (let index = 0; index < 40; index++) hold(spendOf(index, 1));
		expect(sent).to.have.length(0);
		expect(said).to.include(
			`A spend of an output of an asset channel waits for its monitor to be stored (channel ${channelId.toString(
				'hex'
			)})`
		);
		persisted = true;
		release();
		expect(sent.map(outputOf).sort((a, b) => a - b)).to.deep.equal(
			Array.from({ length: 40 }, (_, index) => index)
		);
		// Nothing is held any more, so a second release sends nothing.
		release();
		expect(sent).to.have.length(40);
	});

	it('keeps only the newest form of a spend of one output: a raise replaces the spend it raises', () => {
		for (let index = 0; index < 20; index++) hold(spendOf(index, 1));
		hold(spendOf(3, 2));
		hold(spendOf(3, 3));
		// The same bytes again change nothing.
		hold(spendOf(5, 1));
		persisted = true;
		release();
		expect(sent).to.have.length(20);
		const ofThree = sent.filter((tx) => outputOf(tx) === 3);
		expect(ofThree).to.deep.equal([spendOf(3, 3)]);
		expect(sent.filter((tx) => outputOf(tx) === 5)).to.deep.equal([
			spendOf(5, 1)
		]);
	});

	it('sends a spend at once when the row is stored, as before', () => {
		persisted = true;
		hold(spendOf(0, 1));
		expect(sent).to.deep.equal([spendOf(0, 1)]);
		release();
		expect(sent).to.have.length(1);
	});
});
