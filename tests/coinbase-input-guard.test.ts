/**
 * Coinbase vin guard (issue #548, LFBW port #532 workstream 1F).
 *
 * A coinbase input has no previous output to fetch: its vin carries
 * `coinbase` instead of txid/vout. Mining directly to a wallet address on
 * regtest therefore made the input prefetch ask Electrum for prevouts named
 * undefined:undefined, one invalid-params error per mined block. The vin
 * mapping now skips such entries, and getInputData filters them again at
 * the request boundary so nothing that slips a future mapping can reach the
 * server. Fully offline: with every coinbase-shaped input filtered, the
 * request loop has nothing to send and succeeds without a connection.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import { EProtocol, Wallet } from '../src';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: this test must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

describe('Coinbase input guard (issue #548)', function () {
	this.timeout(30_000);

	let wallet: Wallet;

	before(async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			electrumOptions,
			disableMessagesOnCreate: true
		});
		if (res.isErr()) throw res.error;
		wallet = res.value;
	});

	after(async () => {
		await wallet.stop();
	});

	it('getInputData drops coinbase-shaped inputs instead of querying them', async () => {
		const coinbaseShaped = [
			{
				tx_hash: undefined as unknown as string,
				vout: undefined as unknown as number
			},
			{
				tx_hash: undefined as unknown as string,
				vout: 0
			}
		];
		const res = await wallet.getInputData({ inputs: coinbaseShaped });
		// Unfiltered, these would go to the (unreachable) server and fail;
		// filtered, there is nothing to fetch and the result is an empty ok.
		expect(res.isOk(), res.isErr() ? res.error.message : 'ok').to.equal(true);
		if (res.isOk()) {
			expect(Object.keys(res.value)).to.have.length(0);
		}
	});
});
