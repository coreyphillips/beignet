import { expect } from 'chai';
import * as net from 'net';
import * as tls from 'tls';
import {
	EAddressType,
	EAvailableNetworks,
	Electrum,
	EProtocol,
	err,
	getBitcoinJsNetwork,
	getDefaultPort,
	getElectrumNetwork,
	getKeyDerivationPathString,
	Result,
	validateAddress,
	Wallet
} from '../src';
import { EElectrumNetworks, TConnectToElectrumRes } from '../src/types';
import { Network as LnNetwork } from '../src/lightning/invoice/types';
import { SIGNET_CHAIN_HASH } from '../src/lightning/channel/types';
import { TEST_MNEMONIC } from './constants';

/**
 * Offline signet coverage: network parameters, enum plumbing, derivation
 * vectors and wallet creation. Electrum connects are stubbed so no sockets
 * are opened.
 */

// TEST_MNEMONIC m/84'/1'/0'/0/x. Signet shares testnet's bech32 hrp,
// prefixes and coin type, so these equal the known testnet vectors.
const receive0 = 'tb1qmja98kkd540qtesjqdanfg0ywags845vehfg66';
const receive1 = 'tb1qy45r5c84eh7tuke772lrvj2q5kqlylp2ghgdlk';
const change0 = 'tb1qlqdamfznwfnua735a8jke9ll20dl86aryvuyt9';

describe('Signet support', () => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	let originalDoConnect: any;

	before(() => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		originalDoConnect = (Electrum.prototype as any)._doConnect;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(Electrum.prototype as any)._doConnect = async (): Promise<
			Result<TConnectToElectrumRes>
		> => err('offline test');
	});

	after(() => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(Electrum.prototype as any)._doConnect = originalDoConnect;
	});

	describe('network parameters', () => {
		it('uses testnet address prefixes and BIP32 versions with the tb hrp', () => {
			const signet = getBitcoinJsNetwork(EAvailableNetworks.signet);
			const testnet = getBitcoinJsNetwork(EAvailableNetworks.testnet);
			expect(signet.bech32).to.equal('tb');
			expect(signet.pubKeyHash).to.equal(testnet.pubKeyHash);
			expect(signet.scriptHash).to.equal(testnet.scriptHash);
			expect(signet.wif).to.equal(testnet.wif);
			expect(signet.bip32).to.deep.equal(testnet.bip32);
		});

		it('maps to the bitcoinSignet Electrum network', () => {
			expect(getElectrumNetwork(EAvailableNetworks.signet)).to.equal(
				EElectrumNetworks.bitcoinSignet
			);
		});

		it('uses coin type 1 in derivation paths', () => {
			const path = getKeyDerivationPathString({
				addressType: EAddressType.p2wpkh,
				network: EAvailableNetworks.signet
			});
			if (path.isErr()) throw path.error;
			expect(path.value).to.equal("m/84'/1'/0'/0/0");
		});

		it('uses the signet default Electrum ports', () => {
			expect(getDefaultPort(EAvailableNetworks.signet, 'ssl')).to.equal(60602);
			expect(getDefaultPort(EAvailableNetworks.signet, 'tcp')).to.equal(60601);
		});
	});

	describe('lightning plumbing', () => {
		it('has the tbs invoice prefix in the lightning Network enum', () => {
			expect(LnNetwork.SIGNET).to.equal('tbs');
		});

		it('exposes the signet chain hash (genesis, internal byte order)', () => {
			expect(SIGNET_CHAIN_HASH.toString('hex')).to.equal(
				'f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000'
			);
		});
	});

	describe('wallet on signet', () => {
		let wallet: Wallet;

		before(async () => {
			const res = await Wallet.create({
				mnemonic: TEST_MNEMONIC,
				network: EAvailableNetworks.signet,
				// 'electrum' keeps fee estimation off HTTP while disconnected.
				feeEstimationSource: 'electrum',
				addressTypesToMonitor: [EAddressType.p2wpkh],
				electrumOptions: {
					net,
					tls,
					servers: {
						host: '127.0.0.1',
						ssl: 1,
						tcp: 1,
						protocol: EProtocol.tcp
					}
				}
			});
			if (res.isErr()) throw res.error;
			wallet = res.value;
		});

		after(() => {
			wallet?.electrum.stopConnectionPolling();
		});

		it('derives the expected signet receive addresses', async () => {
			expect(await wallet.getAddress({ index: '0' })).to.equal(receive0);
			expect(await wallet.getAddress({ index: '1' })).to.equal(receive1);
		});

		it('derives the expected signet change address', async () => {
			const address = await wallet.getAddress({
				index: '0',
				changeAddress: true
			});
			expect(address).to.equal(change0);
		});

		it('derives by explicit path with coin type 1', async () => {
			const res = await wallet.getAddressByPath({ path: "m/84'/1'/0'/0/1" });
			if (res.isErr()) throw res.error;
			expect(res.value.address).to.equal(receive1);
		});

		it('validates tb1 addresses on signet', () => {
			expect(wallet.validateAddress(receive0)).to.equal(true);
			expect(
				validateAddress({
					address: receive0,
					network: EAvailableNetworks.signet
				}).isValid
			).to.equal(true);
		});

		it('reports the signet network', () => {
			expect(wallet.network).to.equal(EAvailableNetworks.signet);
			expect(wallet.electrum.electrumNetwork).to.equal(
				EElectrumNetworks.bitcoinSignet
			);
		});
	});
});
