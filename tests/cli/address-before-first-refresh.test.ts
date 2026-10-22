/**
 * Regression test for issue #1783: an address asked for before the wallet's
 * first refresh had stored any addresses read empty address maps and failed
 * with "Reduce of empty array with no initial value". The connection check
 * skips its ping when the server answered recently, so in one process every
 * BeignetNode after the first lost that race.
 *
 * Fully OFFLINE: the wallets point at an unreachable Electrum port, the
 * connection reads as answered recently, and the client helpers answer every
 * history request with no history.
 */

import { expect } from 'chai';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import sinon from 'sinon';
import tls from 'tls';

import {
	createMemoryStorage,
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	IAddress,
	IWalletData,
	ok,
	Wallet
} from '../../src';
import { BeignetNode } from '../../src/cli/beignet-node';

// The raw module.exports object, which src/electrum reads live (see
// broadcast-spent-utxos.test.ts).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const electrumHelpers = require('rn-electrum-client/helpers');

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// Index 0 on each p2wpkh chain of MNEMONIC on regtest.
const FIRST_RECEIVE = 'bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk';

// Unreachable on purpose: this test must work offline. Not remainOffline,
// which refuses the history requests before they reach answerNoHistory.
const ELECTRUM_PORT = 65529;
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: ELECTRUM_PORT,
		tcp: ELECTRUM_PORT,
		protocol: EProtocol.tcp
	}
};

const quiet = {
	debug: (): void => undefined,
	info: (): void => undefined,
	warn: (): void => undefined,
	error: (): void => undefined
};

type TBatch<T> = { key: string; data: T[] };

/** Every script hash asked about has no history. */
const answerNoHistory = (): sinon.SinonStub =>
	sinon
		.stub(electrumHelpers, 'getAddressScriptHashesHistory')
		.callsFake(
			async ({ scriptHashes }: { scriptHashes: TBatch<IAddress> }) => ({
				error: false,
				data: scriptHashes.data.map((a) => ({
					data: a,
					param: a.scriptHash,
					result: []
				}))
			})
		);

/**
 * Connected, and answered within the window that lets the connection check
 * skip its ping, as every node after the first in a process was. That ping is
 * what used to give the first refresh time to store the first window.
 */
const answeredRecently = (wallet: Wallet): sinon.SinonStub => {
	wallet.electrum.stopConnectionPolling();
	wallet.electrum.connectedToElectrum = true;
	wallet.electrum.batchDelay = 0;
	sinon.stub(wallet.electrum, 'answeredRecently').returns(true);
	return sinon.stub(wallet.electrum, 'isConnected').resolves(true);
};

describe('an address asked for before the first refresh (#1783)', function () {
	this.timeout(60000);

	afterEach(() => {
		sinon.restore();
	});

	describe('Wallet.getNextAvailableAddress', () => {
		let wallet: Wallet;
		let ping: sinon.SinonStub;

		beforeEach(async () => {
			const res = await Wallet.create({
				mnemonic: MNEMONIC,
				network: EAvailableNetworks.regtest,
				addressType: EAddressType.p2wpkh,
				addressTypesToMonitor: [EAddressType.p2wpkh],
				electrumOptions,
				// Nothing has refreshed: the address maps are empty.
				disableRefreshOnCreate: true,
				storage: createMemoryStorage()
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
			ping = answeredRecently(wallet);
			answerNoHistory();
		});

		afterEach(async () => {
			sinon.restore();
			await wallet?.stop();
		});

		it('says no addresses are stored yet rather than failing a reduce', () => {
			const res = wallet.getHighestStoredAddressIndex({
				addressType: EAddressType.p2wpkh
			});
			expect(res.isErr()).to.equal(true);
			if (res.isErr()) {
				expect(res.error.message).to.equal('No addresses stored yet.');
			}
		});

		it('derives the first window itself and answers index 0 on both chains', async () => {
			const res = await wallet.getNextAvailableAddress();
			if (res.isErr()) throw res.error;
			expect(ping.callCount, 'the no-ping branch was taken').to.equal(0);
			expect(res.value.addressIndex.index).to.equal(0);
			expect(res.value.addressIndex.address).to.equal(FIRST_RECEIVE);
			expect(res.value.changeAddressIndex.index).to.equal(0);
			expect(res.value.changeAddressIndex.address).to.match(/^bcrt1q/);

			const { lookAhead, lookAheadChange } = wallet.gapLimitOptions;
			const stored = Object.values(wallet.data.addresses.p2wpkh);
			const storedChange = Object.values(wallet.data.changeAddresses.p2wpkh);
			expect(stored.map((a) => a.index).sort((a, b) => a - b)).to.deep.equal([
				...Array(lookAhead).keys()
			]);
			expect(storedChange).to.have.length(lookAheadChange);
		});

		it('answers index 0 when a refresh beside it stores the window first', async () => {
			// What the first refresh's setZeroIndexAddresses does when it wins
			// the race mid-scan: the same window lands in the maps while the
			// scan derives it, so addAddresses answers none of it as added.
			const generate = wallet.generateAddresses.bind(wallet);
			sinon
				.stub(wallet, 'generateAddresses')
				.callsFake(async (...args: Parameters<Wallet['generateAddresses']>) => {
					const res = await generate(...args);
					if (res.isOk()) {
						const { addresses, changeAddresses } = wallet.data;
						const stored = await wallet.updateData({
							addresses: {
								...addresses,
								p2wpkh: { ...addresses.p2wpkh, ...res.value.addresses }
							},
							changeAddresses: {
								...changeAddresses,
								p2wpkh: {
									...changeAddresses.p2wpkh,
									...res.value.changeAddresses
								}
							}
						});
						if (stored.isErr()) throw stored.error;
					}
					return res;
				});

			const res = await wallet.getNextAvailableAddress();
			if (res.isErr()) throw res.error;
			expect(res.value.addressIndex.index).to.equal(0);
			expect(res.value.addressIndex.address).to.equal(FIRST_RECEIVE);
			expect(res.value.changeAddressIndex.index).to.equal(0);
		});
	});

	describe('BeignetNode.getNewAddress straight after create', () => {
		let temp: string;
		const nodes: BeignetNode[] = [];
		let releaseRefreshes = (): void => undefined;

		beforeEach(() => {
			temp = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-1783-'));
			// Each node's first refresh starts in create and is still running
			// when create returns, so it has stored nothing yet.
			const held = new Promise<void>((resolve) => {
				releaseRefreshes = resolve;
			});
			sinon.stub(Wallet.prototype, 'refreshWallet').callsFake(async () => {
				await held;
				return ok({} as IWalletData);
			});
			answerNoHistory();
		});

		afterEach(async () => {
			releaseRefreshes();
			sinon.restore();
			for (const node of nodes.splice(0)) await node.destroy();
			fs.rmSync(temp, { recursive: true, force: true });
		});

		it('gives every node in one process its first receive address', async () => {
			const addresses: string[] = [];
			for (const name of ['a', 'b', 'c']) {
				const node = await BeignetNode.create({
					network: 'regtest',
					dataDir: path.join(temp, name),
					allowMultipleInstances: true,
					electrumHost: '127.0.0.1',
					electrumPort: ELECTRUM_PORT,
					electrumTls: false,
					autoBootstrap: false,
					autoGossipSync: false,
					rapidGossipSync: false,
					logger: quiet
				});
				nodes.push(node);
				const wallet = (node as unknown as { wallet: Wallet }).wallet;
				const addressType = wallet.addressType;
				expect(Object.keys(wallet.data.addresses[addressType])).to.have.length(
					0
				);
				answeredRecently(wallet);

				const address = await node.getNewAddress();
				const first = Object.values(wallet.data.addresses[addressType]).find(
					(a) => a.index === 0
				);
				expect(address, name).to.equal(first?.address);
				addresses.push(address);
			}
			expect(new Set(addresses).size).to.equal(3);
		});
	});
});
