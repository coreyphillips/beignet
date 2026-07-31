import BitcoinJsonRpc from 'bitcoin-json-rpc';
import { expect } from 'chai';
import net from 'net';
import tls from 'tls';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	generateMnemonic,
	sleep,
	Wallet
} from '../';
import {
	bitcoinURL,
	electrumHost,
	electrumPort,
	initWaitForElectrumToSync,
	MessageListener,
	TWaitForElectrum
} from './utils';

const testTimeout = 60000;

/**
 * The transaction message lifecycle, as consumers see it: one appearance per
 * transaction (transactionReceived or transactionSent by direction) and at
 * most one transactionConfirmed, fired only for the transition of a held
 * transaction from the mempool into a block.
 *
 * The case that motivated pinning this: a transaction first discovered
 * already confirmed (found at a catch-up sync after downtime) used to emit
 * transactionConfirmed and then transactionReceived, two messages for one
 * discovery, confirmation first. A consumer modelling the names as lifecycle
 * states regressed from confirmed back to received, and one arrival
 * notified twice.
 */
describe('Transaction message lifecycle', async function () {
	this.timeout(testTimeout);

	let wallet: Wallet | undefined;
	let secondWallet: Wallet | undefined;
	let waitForElectrum: TWaitForElectrum;
	const rpc = new BitcoinJsonRpc(bitcoinURL);
	const ml = new MessageListener();

	const walletOptions = (
		mnemonic: string,
		listener: MessageListener,
		extra: Record<string, unknown> = {}
	): Parameters<typeof Wallet.create>[0] => ({
		mnemonic,
		network: EAvailableNetworks.regtest,
		addressType: EAddressType.p2wpkh,
		electrumOptions: {
			servers: [
				{ host: '127.0.0.1', ssl: 60002, tcp: 60001, protocol: EProtocol.tcp }
			],
			net,
			tls
		},
		// reduce gap limit to speed up tests
		gapLimitOptions: {
			lookAhead: 2,
			lookBehind: 2,
			lookAheadChange: 2,
			lookBehindChange: 2
		},
		addressTypesToMonitor: [EAddressType.p2wpkh],
		onMessage: listener.onMessage,
		...extra
	});

	const txMessages = (
		listener: MessageListener,
		key: string,
		txid?: string
	): unknown[] =>
		listener.messages.filter(
			(m) =>
				m.key === key &&
				(txid === undefined ||
					(m.data as { transaction: { txid: string } }).transaction.txid ===
						txid)
		);

	beforeEach(async function () {
		this.timeout(testTimeout);
		ml.clear();

		let balance = await rpc.getBalance();
		const miner = await rpc.getNewAddress();
		while (balance < 10) {
			await rpc.generateToAddress(10, miner);
			balance = await rpc.getBalance();
		}

		waitForElectrum = await initWaitForElectrumToSync(
			{ host: electrumHost, port: electrumPort },
			bitcoinURL
		);
		await waitForElectrum();

		const res = await Wallet.create(walletOptions(generateMnemonic(), ml));
		if (res.isErr()) throw res.error;
		wallet = res.value;
		await wallet.refreshWallet({});
	});

	afterEach(async function () {
		await wallet?.electrum?.disconnect();
		await secondWallet?.electrum?.disconnect();
		wallet = undefined;
		secondWallet = undefined;
	});

	it('an incoming transaction appears once, then confirms once', async () => {
		const r = await wallet!.getNextAvailableAddress();
		if (r.isErr()) throw r.error;
		const address = r.value.addressIndex.address;

		const receivePromise = ml.waitFor('transactionReceived');
		const txid = await rpc.sendToAddress(address, '0.1');
		await receivePromise;

		expect(txMessages(ml, 'transactionReceived', txid)).to.have.length(1);
		expect(
			txMessages(ml, 'transactionConfirmed', txid),
			'an unconfirmed appearance is not a confirmation'
		).to.have.length(0);

		const confirmedPromise = ml.waitFor('transactionConfirmed');
		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();
		await wallet!.refreshWallet({});
		const confirmed = (await confirmedPromise) as {
			transaction: { txid: string; height: number };
		};
		expect(confirmed.transaction.txid).to.equal(txid);
		expect(confirmed.transaction.height).to.be.greaterThan(0);

		// Settle any stragglers, then hold the counts to exactly one each.
		await sleep(500);
		expect(txMessages(ml, 'transactionReceived', txid)).to.have.length(1);
		expect(txMessages(ml, 'transactionConfirmed', txid)).to.have.length(1);
	});

	it('a transaction discovered already confirmed is one appearance, not a reversed pair', async () => {
		// A wallet whose mnemonic the test holds, so the same wallet can be
		// brought back as a fresh instance after its downtime.
		const mnemonic = generateMnemonic();
		const resA = await Wallet.create(walletOptions(mnemonic, ml));
		if (resA.isErr()) throw resA.error;
		secondWallet = resA.value;
		const r = await secondWallet.getNextAvailableAddress();
		if (r.isErr()) throw r.error;
		const address = r.value.addressIndex.address;

		// The wallet goes offline; money arrives and confirms while nobody
		// watches.
		await secondWallet.electrum.disconnect();
		const txid = await rpc.sendToAddress(address, '0.2');
		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();

		// A fresh instance of the same wallet syncs up. With messages enabled
		// through creation, the catch-up discovery must read as one arrival
		// whose payload already carries the height, not a confirmation of a
		// transaction no consumer has been shown, followed by its appearance.
		const ml2 = new MessageListener();
		const res = await Wallet.create(walletOptions(mnemonic, ml2));
		if (res.isErr()) throw res.error;
		const revived = res.value;
		try {
			await revived.refreshWallet({});
			while (txMessages(ml2, 'transactionReceived', txid).length === 0) {
				await sleep(100);
				await revived.refreshWallet({});
			}

			const received = txMessages(ml2, 'transactionReceived', txid) as Array<{
				data: { transaction: { height: number } };
			}>;
			expect(received).to.have.length(1);
			expect(
				received[0].data.transaction.height,
				'the appearance itself says confirmed'
			).to.be.greaterThan(0);
			expect(
				txMessages(ml2, 'transactionConfirmed', txid),
				'no confirmation fires for a transaction born confirmed'
			).to.have.length(0);
		} finally {
			await revived.electrum.disconnect();
		}
	});

	it('initial sync replays nothing when messages are disabled on create', async () => {
		const mnemonic = generateMnemonic();
		const resA = await Wallet.create(walletOptions(mnemonic, ml));
		if (resA.isErr()) throw resA.error;
		secondWallet = resA.value;
		const r = await secondWallet.getNextAvailableAddress();
		if (r.isErr()) throw r.error;
		const address = r.value.addressIndex.address;

		await secondWallet.electrum.disconnect();
		await rpc.sendToAddress(address, '0.1');
		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();

		// The daemon creates its wallet this way: history is state, not news.
		const ml2 = new MessageListener();
		const res = await Wallet.create(
			walletOptions(mnemonic, ml2, { disableMessagesOnCreate: true })
		);
		if (res.isErr()) throw res.error;
		const revived = res.value;
		try {
			while (revived.balance === 0) {
				await sleep(100);
				await revived.refreshWallet({});
			}
			expect(txMessages(ml2, 'transactionReceived')).to.have.length(0);
			expect(txMessages(ml2, 'transactionSent')).to.have.length(0);
			expect(txMessages(ml2, 'transactionConfirmed')).to.have.length(0);
		} finally {
			await revived.electrum.disconnect();
		}
	});

	it('an outgoing transaction appears as sent, then confirms once', async () => {
		// Fund and confirm first, so the send below is the only pending story.
		const r = await wallet!.getNextAvailableAddress();
		if (r.isErr()) throw r.error;
		await rpc.sendToAddress(r.value.addressIndex.address, '0.1');
		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();
		while (wallet!.balance === 0) {
			await sleep(100);
			await wallet!.refreshWallet({});
		}
		ml.clear();

		const sent = await wallet!.send({
			address: await rpc.getNewAddress(),
			amount: 2_000_000,
			satsPerByte: 2
		});
		if (sent.isErr()) throw sent.error;
		const txid = sent.value;

		while (txMessages(ml, 'transactionSent', txid).length === 0) {
			await sleep(100);
			await wallet!.refreshWallet({});
		}
		expect(txMessages(ml, 'transactionSent', txid)).to.have.length(1);
		expect(
			txMessages(ml, 'transactionReceived', txid),
			'change coming home is not a receive'
		).to.have.length(0);
		expect(txMessages(ml, 'transactionConfirmed', txid)).to.have.length(0);

		await rpc.generateToAddress(1, await rpc.getNewAddress());
		await waitForElectrum();
		while (txMessages(ml, 'transactionConfirmed', txid).length === 0) {
			await sleep(100);
			await wallet!.refreshWallet({});
		}
		await sleep(500);
		expect(txMessages(ml, 'transactionSent', txid)).to.have.length(1);
		expect(txMessages(ml, 'transactionConfirmed', txid)).to.have.length(1);
	});
});
