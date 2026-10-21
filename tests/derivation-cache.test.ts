/**
 * Keys derive through cached account and change nodes, so a new address
 * costs one derivation step and a signed input one (#1660). Fully OFFLINE:
 * the wallets point at an unreachable Electrum port and UTXOs are fabricated
 * for the wallet's own addresses. Expected keys come from a separate bip32
 * instance, whose derivations the spy does not count.
 */

import { expect } from 'chai';
import net from 'net';
import tls from 'tls';
import sinon from 'sinon';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as secp256k1 from '@bitcoinerlab/secp256k1';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

import {
	EAddressType,
	EAvailableNetworks,
	EProtocol,
	getAddressFromKeyPair,
	getScriptHash,
	IGetAddressResponse,
	IUtxo,
	ok,
	Wallet
} from '../src';
import { bip32 as walletBip32 } from '../src/utils/ecc-apis';
import { derivePathCached } from '../src/utils/derive-path-cached';

bitcoin.initEccLib(secp256k1);
const bip32 = BIP32Factory(secp256k1);

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B =
	'legal winner thank year wave sausage worth useful legal winner thank yellow';
const MNEMONIC_C =
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above';
// BIP 173 test vector: a valid regtest address no wallet here owns.
const RECIPIENT = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080';
const regtest = bitcoin.networks.regtest;
const network = EAvailableNetworks.regtest;

// Unreachable on purpose: these tests must work offline.
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

const PURPOSE: Record<Exclude<EAddressType, EAddressType.p2wsh>, number> = {
	p2pkh: 44,
	p2sh: 49,
	p2wpkh: 84,
	p2tr: 86
};

// Every node a wallet holds is an instance of this one class, so a spy on
// its derive sees every derivation step, derivePath's included.
const walletNodes = Object.getPrototypeOf(
	walletBip32.fromSeed(Buffer.alloc(32, 1))
);

const countDerivations = async (
	fn: () => Promise<unknown>
): Promise<{ steps: number; nodes: BIP32Interface[] }> => {
	const spy = sinon.spy(walletNodes, 'derive');
	try {
		await fn();
		return { steps: spy.callCount, nodes: spy.returnValues };
	} finally {
		spy.restore();
	}
};

const root = bip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC), regtest);

const expectedAddress = (
	path: string,
	addressType: EAddressType
): IGetAddressResponse => {
	const res = getAddressFromKeyPair({
		keyPair: root.derivePath(path),
		addressType,
		network: regtest
	});
	if (res.isErr()) throw res.error;
	return { ...res.value, path };
};

const createdWallets: Wallet[] = [];

const track = (res: Awaited<ReturnType<typeof Wallet.create>>): Wallet => {
	if (res.isErr()) throw res.error;
	createdWallets.push(res.value);
	return res.value;
};

describe('Derivation cache (#1660)', function () {
	this.timeout(60000);

	after(async () => {
		sinon.restore();
		await Promise.all(createdWallets.map((w) => w.stop()));
	});

	describe('derivePathCached', () => {
		const PATHS = [
			"m/84'/1'/0'/0/0",
			"m/84'/1'/0'/0/1",
			"m/84'/1'/0'/1/7",
			"m/84'/1'/0'/0",
			"m/48'/1'/0'/2'/0/5",
			"m/084'/1'/0'/0/1",
			"m/84'/1'/0'/0/2147483647",
			"m/0'",
			'0/5',
			'1/2',
			'5',
			// Each of these throws, and must throw what derivePath throws.
			"m/84'/1'/0'/0/2147483648",
			"m/84'/1'/0'/0/4294967296",
			"m/2147483648'",
			"m/84h/0'",
			'm',
			'',
			'0//1'
		];
		const describeNode = (fn: () => BIP32Interface): string => {
			try {
				const node = fn();
				return `${node.toBase58()} ${node.depth} ${node.index} ${
					node.parentFingerprint
				}`;
			} catch (e) {
				return `throws ${(e as Error).message}`;
			}
		};
		const nodes = {
			master: root,
			child: root.derivePath("m/84'/1'/0'"),
			neutered: root.derivePath("m/84'/1'/0'").neutered()
		};

		for (const [name, node] of Object.entries(nodes)) {
			it(`derives what derivePath does from a ${name} node, cold and warm`, () => {
				const branches = new Map<string, BIP32Interface>();
				for (const pass of ['cold', 'warm']) {
					for (const path of PATHS) {
						expect(
							describeNode(() => derivePathCached(node, path, branches)),
							`${pass} ${path}`
						).to.equal(describeNode(() => node.derivePath(path)));
					}
				}
			});
		}

		it('hands out a new leaf every call and never stores one', () => {
			const branches = new Map<string, BIP32Interface>();
			const path = "m/84'/1'/0'/0/3";
			const first = derivePathCached(root, path, branches);
			expect(derivePathCached(root, path, branches)).to.not.equal(first);
			expect([...branches.keys()]).to.deep.equal([
				"m/84'",
				"m/84'/1'",
				"m/84'/1'/0'",
				"m/84'/1'/0'/0"
			]);
		});
	});

	describe('addresses', () => {
		let wallet: Wallet;

		before(async () => {
			wallet = track(
				await Wallet.create({
					mnemonic: MNEMONIC,
					network,
					electrumOptions,
					disableRefreshOnCreate: true
				})
			);
		});

		for (const [addressType, purpose] of Object.entries(PURPOSE)) {
			it(`${addressType}: each new address costs one derivation step`, async () => {
				const type = addressType as EAddressType;
				const account = `m/${purpose}'/1'/0'`;
				// The first address on each branch derives the nodes above it.
				for (const change of [0, 1]) {
					await wallet.getAddressByPath({ path: `${account}/${change}/0` });
				}
				let generated: Awaited<ReturnType<Wallet['generateAddresses']>>;
				const { steps } = await countDerivations(async () => {
					generated = await wallet.generateAddresses({
						addressAmount: 20,
						changeAddressAmount: 20,
						addressIndex: 100,
						changeAddressIndex: 100,
						addressType: type
					});
				});
				expect(steps).to.equal(40);
				if (generated!.isErr()) throw generated!.error;
				const { addresses, changeAddresses } = generated!.value;
				for (const [map, change] of [
					[addresses, 0],
					[changeAddresses, 1]
				] as const) {
					const got = Object.values(map).sort((a, b) => a.index - b.index);
					expect(got).to.have.length(20);
					got.forEach((address, i) => {
						const path = `${account}/${change}/${100 + i}`;
						const { scriptHash: _scriptHash, index: _index, ...rest } = address;
						expect(rest).to.deep.equal(expectedAddress(path, type));
					});
				}
			});
		}

		it('getPrivateKey and derivePublicNode read the same branches', async () => {
			const path = "m/84'/1'/0'/0/250";
			const expected = root.derivePath(path);
			const { steps } = await countDerivations(async () => {
				expect(wallet.getPrivateKey(path)).to.equal(expected.toWIF());
				const node = wallet.derivePublicNode(path);
				if (node.isErr()) throw node.error;
				expect(node.value.publicKey).to.deep.equal(expected.publicKey);
				expect(node.value.isNeutered()).to.equal(true);
			});
			expect(steps).to.equal(2);
		});
	});

	describe('signing', () => {
		for (const addressType of [EAddressType.p2wpkh, EAddressType.p2tr]) {
			it(`${addressType}: a send derives each input's key once`, async () => {
				const wallet = track(
					await Wallet.create({
						mnemonic: MNEMONIC,
						network,
						addressType,
						electrumOptions,
						disableRefreshOnCreate: true
					})
				);
				// The offline refresh still stores the index-0 addresses,
				// including the change address the send needs.
				await wallet.refreshWallet({});
				const purpose = PURPOSE[addressType as keyof typeof PURPOSE];
				const utxos: IUtxo[] = [];
				for (const [index, value] of [40000, 35000, 30000].entries()) {
					const path = `m/${purpose}'/1'/0'/0/${index}`;
					const { address, publicKey } = expectedAddress(path, addressType);
					const utxo: IUtxo = {
						address,
						index,
						path,
						scriptHash: getScriptHash({ address, network }),
						height: 100,
						tx_hash: Buffer.from(
							bitcoin.crypto.sha256(Buffer.from(`utxo-${addressType}-${index}`))
						).toString('hex'),
						tx_pos: 0,
						value,
						publicKey
					};
					wallet.data.utxos.push(utxo);
					wallet.data.balance += value;
					utxos.push(utxo);
				}

				let signed: Awaited<ReturnType<Wallet['send']>>;
				const { steps, nodes } = await countDerivations(async () => {
					// 100k needs all three coins.
					signed = await wallet.send({
						address: RECIPIENT,
						amount: 100000,
						satsPerByte: 2,
						broadcast: false,
						shuffleOutputs: false
					});
				});
				if (signed!.isErr()) throw signed!.error;
				// One key per input, plus the four nodes above them, which the
				// send derives once from its own copy of the root.
				const leaves = nodes.filter((node) => node.depth === 5);
				expect(leaves.map((node) => node.index).sort()).to.deep.equal([
					0, 1, 2
				]);
				expect(steps).to.equal(utxos.length + 4);

				// The same bytes a root nothing has cached signs.
				await wallet.resetSendTransaction();
				const stub = sinon
					.stub(wallet, 'getBip32Interface')
					.resolves(
						ok(
							walletBip32.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC), regtest)
						)
					);
				try {
					const again = await wallet.send({
						address: RECIPIENT,
						amount: 100000,
						satsPerByte: 2,
						broadcast: false,
						shuffleOutputs: false
					});
					if (again.isErr()) throw again.error;
					expect(again.value).to.equal(signed!.value);
				} finally {
					stub.restore();
				}
			});
		}
	});

	describe('multisig', () => {
		const ACCOUNT_PATH = "m/48'/1'/0'/2'";
		const roots = [MNEMONIC, MNEMONIC_B, MNEMONIC_C].map((mnemonic) =>
			bip32.fromSeed(bip39.mnemonicToSeedSync(mnemonic), regtest)
		);
		const xpub = (node: BIP32Interface): string =>
			node.derivePath(ACCOUNT_PATH).neutered().toBase58();

		it('each new address costs one derivation step per cosigner', async () => {
			const wallet = track(
				await Wallet.createMultisig({
					threshold: 2,
					mnemonic: MNEMONIC,
					cosigners: [xpub(roots[1]), xpub(roots[2])],
					network,
					electrumOptions,
					disableRefreshOnCreate: true
				})
			);
			await wallet.getAddress({ index: '0' });
			for (const index of [40, 41, 42]) {
				let address = '';
				const { steps } = await countDerivations(async () => {
					address = await wallet.getAddress({ index: String(index) });
				});
				expect(steps).to.equal(3);
				const pubkeys = roots
					.map((r) => r.derivePath(`${ACCOUNT_PATH}/0/${index}`).publicKey)
					.sort((a, b) => a.compare(b));
				const p2wsh = bitcoin.payments.p2wsh({
					redeem: bitcoin.payments.p2ms({ m: 2, pubkeys, network: regtest }),
					network: regtest
				});
				expect(address).to.equal(p2wsh.address);
			}
		});
	});

	describe('watch-only', () => {
		it('each new address costs one derivation step', async () => {
			const wallet = track(
				await Wallet.createWatchOnly({
					xpub: root.derivePath("m/84'/1'/0'").neutered().toBase58(),
					network,
					electrumOptions,
					disableRefreshOnCreate: true
				})
			);
			await wallet.getAddress({ index: '0' });
			for (const index of [60, 61, 62]) {
				const path = `m/84'/1'/0'/0/${index}`;
				let res: Awaited<ReturnType<Wallet['getAddressByPath']>>;
				const { steps } = await countDerivations(async () => {
					res = await wallet.getAddressByPath({ path });
				});
				expect(steps).to.equal(1);
				if (res!.isErr()) throw res!.error;
				expect(res!.value).to.deep.equal(
					expectedAddress(path, EAddressType.p2wpkh)
				);
			}
		});
	});

	describe('customGetAddress', () => {
		it("returns the host's answer and derives nothing itself", async () => {
			const asked: string[] = [];
			const wallet = track(
				await Wallet.create({
					mnemonic: MNEMONIC,
					network,
					electrumOptions,
					disableRefreshOnCreate: true,
					customGetAddress: async ({ path, type }) => {
						asked.push(path);
						return ok(expectedAddress(path, type));
					}
				})
			);
			const path = "m/84'/1'/0'/0/9";
			let res: Awaited<ReturnType<Wallet['getAddressByPath']>>;
			const { steps } = await countDerivations(async () => {
				res = await wallet.getAddressByPath({ path });
			});
			expect(steps).to.equal(0);
			expect(asked).to.include(path);
			if (res!.isErr()) throw res!.error;
			expect(res!.value).to.deep.equal(
				expectedAddress(path, EAddressType.p2wpkh)
			);
		});
	});
});
